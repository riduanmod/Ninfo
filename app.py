import asyncio
import time
import httpx
import json
import os
import sys
import platform
import base64
import logging
from datetime import datetime
from collections import defaultdict
from functools import wraps
from typing import Tuple

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from cachetools import TTLCache
from Crypto.Cipher import AES

# ==========================================
# LOGGING CONFIGURATION
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# ==========================================
# SYSTEM CONFIG & PATH SETUP
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Import game version configuration
try:
    import game_version
except ImportError as e:
    logger.error(f"Configuration import error: {e}. Please ensure 'game_version.py' exists in the root directory.")
    sys.exit(1)

PROTO_DIR = os.path.join(BASE_DIR, 'proto')
if PROTO_DIR not in sys.path:
    sys.path.append(PROTO_DIR)

try:
    from Pb2 import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
    from google.protobuf import json_format, message
    from google.protobuf.message import Message
except ImportError as e:
    logger.error(f"Protobuf import error: {e}. Please ensure compiled proto files exist in the 'proto' directory.")
    sys.exit(1)

# ==========================================
# CONSTANTS & CONFIGURATION (DYNAMIC FROM game_version.py)
# ==========================================
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

# Dynamically assigned from game_version.py
RELEASEVERSION = game_version.RELEASE_VERSION
UNITYVERSION = game_version.UNITY_VERSION

# Constructing User-Agent dynamically based on OS and Device Model
USERAGENT = f"Dalvik/2.1.0 (Linux; U; {game_version.ANDROID_OS_VERSION}; {game_version.USER_AGENT_MODEL} Build/RKQ1.211119.001)"

SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

app = Flask(__name__)
CORS(app)

# In-memory Caching (TTL = 5 minutes)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
uid_region_cache = {}

# ==========================================
# TIMESTAMP CONVERTER HELPER
# ==========================================
def format_timestamp(ts):
    """Converts Unix epoch timestamp to a readable Date & Time format."""
    if not ts:
        return None
    try:
        dt_object = datetime.fromtimestamp(int(ts))
        return dt_object.strftime("%Y-%m-%d %I:%M:%S %p")
    except Exception:
        return str(ts) 

# ==========================================
# CORE LOGIC & ENCRYPTION
# ==========================================
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

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=3933356115&password=CA6DDAEE7F32A95D6BC17B15B8D5C59E091338B4609F25A1728720E8E4C107C4"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=4044223479&password=EB067625F1E2CB705C7561747A46D502480DC5D41497F4C90F3FDBC73B8082ED"
    else:
        return "uid=4108414251&password=E4F9C33BBEB23C0DA0AD7E60F63C8A05D6A878798E3CD32C4E2314C1EEFD4F72"

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip", 
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    body = json.dumps({
        "open_id": open_id, 
        "open_id_type": "4", 
        "login_token": token_val, 
        "orign_platform_type": "4"
    })
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 
        'Expect': "100-continue", 
        'X-Unity-Version': UNITYVERSION,   # Dynamic
        'X-GA': "v1 1", 
        'ReleaseVersion': RELEASEVERSION   # Dynamic
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        resp.raise_for_status()
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
        
        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25000 
        }

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    
    headers = {
        'User-Agent': USERAGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 
        'Expect': "100-continue",
        'Authorization': token, 
        'X-Unity-Version': UNITYVERSION,  # Dynamic
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION  # Dynamic
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
        resp.raise_for_status()
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

# ==========================================
# DATA TRANSFORMER / ADAPTER (100% EXHAUSTIVE STRUCTURED FORMAT)
# ==========================================
class FreeFireResponseFormatter:
    """
    Transforms raw Protobuf JSON into the precise categorized structure 
    requested by the user, explicitly including ALL parameters available.
    """
    @staticmethod
    def format_profile_data(raw_data: dict) -> dict:
        if not raw_data:
            return {"error": "No data found", "message": "Failed to parse API data."}

        basic_info = raw_data.get("basicInfo", {})
        profile_info = raw_data.get("profileInfo", {})
        clan_info = raw_data.get("clanBasicInfo", {})
        captain_info = raw_data.get("captainBasicInfo", {})
        pet_info = raw_data.get("petInfo", {})
        social_info = raw_data.get("socialInfo", {})
        credit_score = raw_data.get("creditScoreInfo", {})
        diamond_res = raw_data.get("diamondCostRes", {})

        formatted_response = {
            "Player Information": {
                "Player_Name": basic_info.get("nickname"),
                "Player_UID": basic_info.get("accountId"),
                "Player_Level": basic_info.get("level", 0),
                "Player_EXP": basic_info.get("exp", 0),
                "Player_Likes": basic_info.get("liked", 0),
                "Player_Region": basic_info.get("region"),
                "Player_Gender": social_info.get("gender"),
                "Player_Language": social_info.get("language"),
                "Account_Create_Time": format_timestamp(basic_info.get("createAt")),
                "Account_Last_Login": format_timestamp(basic_info.get("lastLoginAt")),
                "Season_ID": basic_info.get("seasonId"),
                "Player_Title": basic_info.get("title"),
                "Player_BP_Badges": basic_info.get("badgeCnt", 0),
                "Player_BP_ID": basic_info.get("badgeId"),
                "Player_Signature": social_info.get("signature", "").strip()
            },
            "Account Profile & Credit": {
                "Player_Credit_Score": credit_score.get("creditScore", 100),
                "Player_Credit_Status": credit_score.get("rewardState"),
                "Credit_Summary_End_Time": format_timestamp(credit_score.get("periodicSummaryEndTime")),
                "Player_Equipped_Outfit": profile_info.get("clothes", []),
                "Player_Equipped_Skills": profile_info.get("equipedSkills", []),
                "Player_Equipped_Weapon": basic_info.get("weaponSkinShows", []),
                "Player_Equipped_Achievements": raw_data.get("equippedAch", [])
            },
            "Appearance Information": {
                "Banner_ID": basic_info.get("bannerId"),
                "Avatar_ID": basic_info.get("headPic"),
                "Character_ID": profile_info.get("avatarId"),
                "Skin_Color": profile_info.get("skinColor"),
                "Player_Is_Selected": profile_info.get("isSelected"),
                "Player_Is_Selected_Awaken": profile_info.get("isSelectedAwaken"),
                "Player_Unlock_Time": format_timestamp(profile_info.get("unlockTime"))
            },
            "Rank Information": {
                "BR_Rank": basic_info.get("rank", 0),
                "BR_Rank_Point": basic_info.get("rankingPoints", 0),
                "BR_Max_Rank": basic_info.get("maxRank", 0),
                "BR_Show_Rank": basic_info.get("showBrRank"),
                "CS_Rank": basic_info.get("csRank", 0),
                "CS_Rank_Point": basic_info.get("csRankingPoints", 0),
                "CS_Max_Rank": basic_info.get("csMaxRank", 0),
                "CS_Show_Rank": basic_info.get("showCsRank"),
                "Rank_Show_Preference": social_info.get("rankShow"),
                "Player_Hippo_Rank": basic_info.get("periodicRank"),
                "Player_Hippo_Points": basic_info.get("periodicRankingPoints")
            },
            "Pet Information": {
                "Pet_Name": pet_info.get("name"),
                "Pet_ID": pet_info.get("id"),
                "Pet_Level": pet_info.get("level", 0),
                "Pet_EXP": pet_info.get("exp", 0),
                "Pet_Skin_ID": pet_info.get("skinId"),
                "Pet_Selected_Skill_ID": pet_info.get("selectedSkillId"),
                "Pet_Is_Selected": pet_info.get("isSelected")
            },
            "Guild Information": {
                "Guild_Name": clan_info.get("clanName"),
                "Guild_ID": clan_info.get("clanId"),
                "Guild_Level": clan_info.get("clanLevel", 0),
                "Guild_Capacity": clan_info.get("capacity", 0),
                "Guild_Total_Members": clan_info.get("memberNum", 0),
                "Guild_Leader_UID": clan_info.get("captainId")
            },
            "Guild Leader Information": {
                "Guild_Leader_Name": captain_info.get("nickname") if captain_info else None,
                "Guild_Leader_UID": captain_info.get("accountId") if captain_info else None,
                "Guild_Leader_Level": captain_info.get("level", 0) if captain_info else None,
                "Guild_Leader_EXP": captain_info.get("exp", 0) if captain_info else None,
                "Guild_Leader_Likes": captain_info.get("liked", 0) if captain_info else None,
                "Guild_Leader_Last_Login": format_timestamp(captain_info.get("lastLoginAt")) if captain_info else None,
                "Guild_Leader_Create_Time": format_timestamp(captain_info.get("createAt")) if captain_info else None,
                "Guild_Leader_BR_Rank": captain_info.get("rank", 0) if captain_info else None,
                "Guild_Leader_CS_Rank": captain_info.get("csRank", 0) if captain_info else None,
                "Guild_Leader_Banner_ID": captain_info.get("bannerId") if captain_info else None,
                "Guild_Leader_Avatar_ID": captain_info.get("headPic") if captain_info else None
            },
            "Extended Stats & Info": {
                "Account_Prefers": basic_info.get("accountPrefers", {}),
                "External_Icon_Info": basic_info.get("externalIconInfo", {}),
                "Social_Highlights": basic_info.get("socialHighLightsWithBasicInfo", {}),
                "Diamond_Cost": diamond_res.get("diamondCost", 0)
            },
            "Technical Information": {
                "Release_Version": basic_info.get("releaseVersion"),
                "Account_Type": basic_info.get("accountType")
            }
        }

        return formatted_response

# ==========================================
# API DECORATORS
# ==========================================
def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(sorted(request.args.items())))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            # Cache only successful JSON responses
            if isinstance(res, Response) and res.status_code == 200:
                cache[key] = res
            return res
        return wrapper
    return decorator

# ==========================================
# FLASK ROUTES & API ENDPOINTS
# ==========================================

@app.route('/', methods=['GET'])
def api_health_check():
    """Health check endpoint for the API."""
    return jsonify({
        "status": "online",
        "service": "Free Fire Profile API Final Structured",
        "message": "API is running successfully."
    }), 200

@app.route('/player-info', methods=['GET'])
@cached_endpoint()
def get_account_info():
    """Main endpoint to fetch player information based on UID."""
    uid = request.args.get('uid')
    response_format = request.args.get('format', 'custom').lower() 
    
    if not uid:
        return jsonify({"error": "Bad Request", "message": "Please provide a valid 'uid' query parameter."}), 400

    def process_response(raw_data):
        if response_format == 'custom':
            return FreeFireResponseFormatter.format_profile_data(raw_data)
        return raw_data

    if uid in uid_region_cache:
        try:
            return_data = asyncio.run(GetAccountInformation(uid, "7", uid_region_cache[uid], "/GetPlayerPersonalShow"))
            final_data = process_response(return_data)
            return Response(json.dumps(final_data, ensure_ascii=False, indent=2), status=200, mimetype='application/json; charset=utf-8')
        except Exception as e:
            logger.warning(f"Cached region failed for UID {uid}: {str(e)}")
            pass

    for region in SUPPORTED_REGIONS:
        try:
            return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
            uid_region_cache[uid] = region 
            final_data = process_response(return_data)
            return Response(json.dumps(final_data, ensure_ascii=False, indent=2), status=200, mimetype='application/json; charset=utf-8')
        except Exception:
            continue

    logger.error(f"UID {uid} not found in any supported region.")
    return jsonify({"error": "Not Found", "message": "UID not found in any supported region."}), 404

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    """Endpoint to forcefully refresh JWT tokens for all regions."""
    try:
        logger.info("Token refresh triggered.")
        tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
        asyncio.run(asyncio.gather(*tasks))
        return jsonify({
            'status': 'success',
            'message': 'Tokens refreshed successfully for all supported regions.'
        }), 200
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        return jsonify({
            'error': 'Internal Server Error',
            'message': f'Token refresh failed: {str(e)}'
        }), 500

# ==========================================
# ENTRY POINT
# ==========================================
if __name__ == '__main__':
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting API Server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
