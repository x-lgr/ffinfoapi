import asyncio
import time
import httpx
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple, Optional
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
from functools import wraps
from collections import defaultdict

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB52"
USERAGENT = "ART/2.2.0 (Linux; U; Android 14; SAMSUNG_S25 Build/UP1A.240905.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)

# Simple in-memory cache (will reset on each cold start)
cache = TTLCache(maxsize=100, ttl=300)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

def json_to_proto_sync(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=3197059560&password=3EC146CD4EEF7A640F2967B06D7F4413BD4FB37382E0ED260E214E8BACD96734"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=3939493997&password=D08775EC0CCCEA77B2426EBC4CF04C097E0D58822804756C02738BF37578EE17"
    else:
        return "uid=3937206629&password=E4D17A3799816184A9BA20C68D8DE55C69180F8C793CA1C6B164C6D14848D8DF"

# === Synchronous Token Generation (for Vercel) ===
def get_access_token_sync(account: str):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    
    with httpx.Client() as client:
        resp = client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

def create_jwt_sync(region: str):
    account = get_account_credentials(region)
    token_val, open_id = get_access_token_sync(account)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = json_to_proto_sync(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1",
               'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION}
    
    with httpx.Client() as client:
        resp = client.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
        return {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
        }

def get_token_info_sync(region: str) -> Tuple[str, str, str]:
    # Try to get from cache first
    cached = app.config.get('cached_tokens', {})
    if region in cached:
        info = cached[region]
        if time.time() < info['expires_at']:
            return info['token'], info['region'], info['server_url']
    
    # Create new token
    token_data = create_jwt_sync(region)
    
    # Store in cache (using app config as simple storage)
    if not hasattr(app, 'config'):
        app.config['cached_tokens'] = {}
    
    app.config['cached_tokens'][region] = {
        **token_data,
        'expires_at': time.time() + 25200
    }
    
    return token_data['token'], token_data['region'], token_data['server_url']

def GetAccountInformationSync(uid, unk, region, endpoint):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    
    payload = json_to_proto_sync(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = get_token_info_sync(region)
    
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue",
               'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
               'ReleaseVersion': RELEASEVERSION}
    
    with httpx.Client() as client:
        resp = client.post(server + endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

# === Caching Decorator ===
def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# === Flask Routes ===
@app.route('/')
def home():
    return "API is alive on Vercel!", 200

@app.route('/get')
@cached_endpoint()
def get_account_info():
    region = request.args.get('region')
    uid = request.args.get('uid')

    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    # If no region specified, try all regions
    if not region:
        for reg in SUPPORTED_REGIONS:
            try:
                return_data = GetAccountInformationSync(uid, "7", reg, "/GetPlayerPersonalShow")
                formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
                response = app.make_response(formatted_json)
                response.headers['Content-Type'] = 'application/json; charset=utf-8'
                response.headers['X-Detected-Region'] = reg
                return response
            except Exception:
                continue
        return jsonify({"error": "UID not found in any supported region."}), 404

    try:
        return_data = GetAccountInformationSync(uid, "7", region, "/GetPlayerPersonalShow")
        formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
        response = app.make_response(formatted_json)
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        return response
    except Exception as e:
        return jsonify({"error": "Invalid UID or Region. Please check and try again."}), 500

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        # Clear cached tokens
        app.config['cached_tokens'] = {}
        return jsonify({'message': 'Tokens cache cleared for all regions.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

# For local development
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
