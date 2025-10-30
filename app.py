import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
from flask import Flask, request, jsonify, Response
import requests
import json
from datetime import datetime
import os
import time
import asyncio
import aiohttp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
from proto import like_pb2, like_count_pb2, uid_generator_pb2
from google.protobuf.message import DecodeError
import urllib3
from collections import OrderedDict

# Configurações
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)

# 🔥 DESABILITAR ORDENAÇÃO AUTOMÁTICA DO FLASK
app.config['JSON_SORT_KEYS'] = False

TOKENS_API_BASE_URL = "http://us-03.hostmine.com.br:20234/tokens"
MAX_LIKES = 100
MAX_CONCURRENT_REQUESTS = 100

# 🔥 CONFIGURAÇÃO DAS REGIÕES
ALL_REGIONS = {
    "IND": "https://client.ind.freefiremobile.com",
    "ID": "https://clientbp.ggblueshark.com",
    "BR": "https://client.us.freefiremobile.com",
    "ME": "https://clientbp.common.ggbluefox.com",
    "VN": "https://clientbp.ggblueshark.com",
    "TH": "https://clientbp.common.ggbluefox.com",
    "CIS": "https://clientbp.ggblueshark.com",
    "BD": "https://clientbp.ggblueshark.com",
    "PK": "https://clientbp.ggblueshark.com",
    "SG": "https://clientbp.ggblueshark.com",
    "NA": "https://client.us.freefiremobile.com",
    "SAC": "https://client.us.freefiremobile.com",
    "EU": "https://clientbp.ggblueshark.com",
    "TW": "https://clientbp.ggblueshark.com"
}

# 🔧 BUSCAR TOKENS DA API NODE.JS
def load_tokens(server_name):
    """Busca tokens diretamente da API Node.js"""
    try:
        url = f"{TOKENS_API_BASE_URL}/{server_name.lower()}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success") and "tokens" in data:
                tokens = []
                for token_obj in data["tokens"]:
                    tokens.append({
                        "access_token": token_obj["token"],
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                print(f"✅ Carregados {len(tokens)} tokens do servidor {server_name}")
                return tokens
            else:
                print(f"❌ API retornou erro para {server_name}: {data}")
                return []
        else:
            print(f"❌ Falha ao buscar tokens {server_name}: Status {response.status_code}")
            return []
            
    except Exception as e:
        print(f"❌ Erro ao carregar tokens {server_name} da API: {e}")
        return []

# 🔥🔥🔥 SISTEMA DE LIKES ULTRA-RÁPIDO
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def decode_protobuf(binary):
    try:
        if not binary or len(binary) == 0:
            return None
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        return None
    except Exception as e:
        return None

async def send_request(encrypted_uid, token, url, session, semaphore):
    """🔥 ENVIO ULTRA-RÁPIDO com sessão reutilizável"""
    async with semaphore:
        try:
            edata = bytes.fromhex(encrypted_uid)
            headers = {
                'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                'Connection': "Keep-Alive",
                'Accept-Encoding': "gzip",
                'Authorization': f"Bearer {token}",
                'Content-Type': "application/x-www-form-urlencoded",
                'Expect': "100-continue",
                'X-Unity-Version': "2018.4.11f1",
                'X-GA': "v1 1",
                'ReleaseVersion': "OB50"
            }
            
            timeout = aiohttp.ClientTimeout(total=5, connect=2, sock_read=3)
            
            async with session.post(url, data=edata, headers=headers, ssl=False, timeout=timeout) as response:
                return response.status
                
        except asyncio.TimeoutError:
            return "Timeout"
        except Exception as e:
            return f"Error: {str(e)}"

async def send_multiple_requests(uid, server_name, url):
    """⚡ ENVIO EM MASSA OTIMIZADO"""
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            return None
        
        tokens = load_tokens(server_name)
        if not tokens or len(tokens) == 0:
            return {"error": "Nenhum token disponível"}
        
        tokens_to_use = tokens[:101]
        actual_likes = min(MAX_LIKES, len(tokens_to_use) - 1)
        
        print(f"🎯 ENVIO ULTRA-RÁPIDO {server_name}: {actual_likes} likes...")
        
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        timeout = aiohttp.ClientTimeout(total=5)
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=100, ttl_dns_cache=300)
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = []
            for i in range(actual_likes):
                token = tokens_to_use[i]["access_token"]
                task = send_request(encrypted_uid, token, url, session, semaphore)
                tasks.append(task)
            
            start_time = time.time()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            end_time = time.time()
            
            successful = 0
            failed = 0
            for result in results:
                if result == 200:
                    successful += 1
                else:
                    failed += 1
            
            time_taken = end_time - start_time
            
            return {
                "total_requests": actual_likes,
                "successful": successful,
                "failed": failed,
                "time_taken_seconds": round(time_taken, 2),
                "likes_per_second": round(successful / time_taken, 2) if time_taken > 0 else 0
            }
        
    except Exception as e:
        return {"error": f"Erro no envio em massa: {str(e)}"}

def make_request(encrypt, server_name, token):
    try:
        # Usa a URL da região configurada
        base_url = ALL_REGIONS.get(server_name, "https://clientbp.ggblueshark.com")
        url = f"{base_url}/GetPlayerPersonalShow"
        
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=15)
        
        if not response.content:
            return None
            
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
            
        return decode
        
    except Exception as e:
        return None

def create_ordered_response(data):
    """🔥 FUNÇÃO QUE GARANTE A ORDEM EXATA"""
    ordered_data = [
        ("👤 • Nome", data["nome"]),
        ("🆔 • UID", data["uid"]),
        ("🌍 • Região", data["regiao"]),
        ("📊 • Likes Antes", data["likes_antes"]),
        ("🔄 • Likes Agora", data["likes_agora"]),
        ("📨 • Likes Recebidos", data["likes_recebidos"]),
        ("⏱️ • Velocidade", data["velocidade"]),
        ("📋 • Status", data["status"])
    ]
    
    # Criar JSON manualmente para garantir ordem
    json_string = "{\n"
    for i, (key, value) in enumerate(ordered_data):
        if isinstance(value, str):
            json_string += f'  "{key}": "{value}"'
        else:
            json_string += f'  "{key}": {value}'
        
        if i < len(ordered_data) - 1:
            json_string += ",\n"
        else:
            json_string += "\n"
    json_string += "}"
    
    return json_string

# 🎯 ROTA PRINCIPAL COM ORDEM GARANTIDA
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    
    if not uid or not server_name:
        error_data = {
            "nome": "Erro",
            "uid": 0,
            "regiao": "N/A",
            "likes_antes": 0,
            "likes_agora": 0,
            "likes_recebidos": 0,
            "velocidade": "0 segundos",
            "status": "Erro: UID e server_name são obrigatórios"
        }
        response_json = create_ordered_response(error_data)
        return Response(response_json, mimetype='application/json'), 400

    try:
        start_time = time.time()
        
        # Buscar tokens da região
        tokens = load_tokens(server_name)
        if not tokens:
            raise Exception(f"Nenhum token disponível para a região {server_name}")
        
        import random
        token = random.choice(tokens)['access_token']
        
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            raise Exception("Falha na criptografia do UID.")

        # URL da região
        base_url = ALL_REGIONS.get(server_name, "https://clientbp.ggblueshark.com")
        
        # ⚡ VERIFICAÇÃO RÁPIDA ANTES
        before = make_request(encrypted_uid, server_name, token)
        if before is None:
            raise Exception("Falha ao recuperar informações iniciais do jogador.")
        
        try:
            jsone = MessageToJson(before)
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            before_like = int(before_like) if before_like else 0
            player_name = data_before.get('AccountInfo', {}).get('PlayerNickname', 'Desconhecido')
            player_uid = data_before.get('AccountInfo', {}).get('UID', uid)
        except Exception as e:
            before_like = 0
            player_name = "Desconhecido"
            player_uid = uid

        # 🔥 ENVIO ULTRA-RÁPIDO DE LIKES
        like_url = f"{base_url}/LikeProfile"
        send_results = asyncio.run(send_multiple_requests(uid, server_name, like_url))

        # ⚡ VERIFICAÇÃO RÁPIDA DEPOIS
        after = make_request(encrypted_uid, server_name, token)
        if after is None:
            raise Exception("Falha ao recuperar informações do jogador após os likes.")
        
        try:
            jsone_after = MessageToJson(after)
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
        except Exception as e:
            after_like = before_like

        like_given = after_like - before_like
        status = 1 if like_given > 0 else 2
        
        end_time = time.time()
        total_time = round(end_time - start_time, 2)
        
        # ✅ DADOS PARA A RESPOSTA
        response_data = {
            "nome": player_name,
            "uid": player_uid,
            "regiao": server_name,
            "likes_antes": before_like,
            "likes_agora": after_like,
            "likes_recebidos": like_given,
            "velocidade": f"{total_time} segundos",
            "status": "1 - Likes enviados com sucesso!" if status == 1 else "2 - Não foram enviados nenhum like!"
        }
        
        # 🔥 CRIAR RESPOSTA COM ORDEM GARANTIDA
        response_json = create_ordered_response(response_data)
        return Response(response_json, mimetype='application/json')
        
    except Exception as e:
        error_data = {
            "nome": "Erro",
            "uid": 0,
            "regiao": server_name,
            "likes_antes": 0,
            "likes_agora": 0,
            "likes_recebidos": 0,
            "velocidade": "0 segundos",
            "status": f"Erro: {str(e)}"
        }
        response_json = create_ordered_response(error_data)
        return Response(response_json, mimetype='application/json'), 500

# Rota inicial
@app.route("/")
def home():
    return jsonify({
        "message": "🚀 API Free Fire - Sistema de Likes",
        "endpoint": "/like?uid=SEU_UID&server_name=REGIAO",
        "regioes": list(ALL_REGIONS.keys()),
        "credits": "Dev By Coringa"
    })

from app import app

# Para o Vercel
application = app

if __name__ == '__main__':
    app.run()
