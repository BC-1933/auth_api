from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import sqlite3
import secrets
import hashlib
import datetime
import jwt
import os
from functools import wraps

app = Flask(__name__)
CORS(app)

# Configurações
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DATABASE = "auth.db"

# Inicializar banco de dados
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Tabela de usuários
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_owner BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Tabela de chaves
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_code TEXT UNIQUE NOT NULL,
            hwid_hash TEXT,
            hwid_reset_count INTEGER DEFAULT 0,
            pause_count INTEGER DEFAULT 0,
            is_paused BOOLEAN DEFAULT 0,
            duration_hours INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            first_login_at TIMESTAMP,
            expires_at TIMESTAMP,
            paused_at TIMESTAMP,
            paused_duration INTEGER DEFAULT 0,
            created_by TEXT
        )
    """)
    
    # Tabela de permissões
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            can_use_all_commands BOOLEAN DEFAULT 0,
            can_generate_keys BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Tabela de logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_type TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    conn.close()

# Função para hash de senha
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Função para hash de HWID
def hash_hwid(hwid):
    return hashlib.sha256(hwid.encode()).hexdigest()

# Decorator para autenticação
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"message": "Token ausente"}), 401
        try:
            token = token.replace("Bearer ", "")
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data["username"]
        except:
            return jsonify({"message": "Token inválido"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Rota principal - Status da API
@app.route("/")
def index():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Auth API Status</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                text-align: center;
            }
            h1 {
                color: #667eea;
                margin-bottom: 20px;
            }
            .status {
                font-size: 24px;
                color: #28a745;
                font-weight: bold;
            }
            .info {
                margin-top: 20px;
                color: #666;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Auth API</h1>
            <div class="status">✓ Online</div>
            <div class="info">
                <p>API de autenticação funcionando corretamente</p>
                <p>Versão: 1.0.0</p>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html)

# Rota de login
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    key_code = data.get("key")
    hwid = data.get("hwid")
    
    if not key_code or not hwid:
        return jsonify({"success": False, "message": "Chave e HWID são obrigatórios"}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Buscar chave
    cursor.execute("SELECT * FROM keys WHERE key_code = ?", (key_code,))
    key_data = cursor.fetchone()
    
    if not key_data:
        conn.close()
        log_login(key_code, hwid, False, "Chave não encontrada")
        return jsonify({"success": False, "message": "Chave inválida"}), 401
    
    key_id, code, hwid_hash_stored, hwid_reset_count, pause_count, is_paused, duration_hours, created_at, first_login_at, expires_at, paused_at, paused_duration, created_by = key_data
    
    # Verificar se está pausada
    if is_paused:
        conn.close()
        log_login(key_code, hwid, False, "Chave pausada")
        return jsonify({"success": False, "message": "Chave pausada"}), 403
    
    hwid_hash_input = hash_hwid(hwid)
    
    # Primeiro login - registrar HWID
    if not hwid_hash_stored:
        cursor.execute("""
            UPDATE keys 
            SET hwid_hash = ?, first_login_at = ?, expires_at = ?
            WHERE key_code = ?
        """, (hwid_hash_input, datetime.datetime.now(), 
              datetime.datetime.now() + datetime.timedelta(hours=duration_hours), key_code))
        conn.commit()
        conn.close()
        
        token = jwt.encode({"username": key_code, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, 
                          SECRET_KEY, algorithm="HS256")
        log_login(key_code, hwid, True, "Primeiro login bem-sucedido")
        return jsonify({"success": True, "message": "Login bem-sucedido", "token": token}), 200
    
    # Verificar HWID
    if hwid_hash_stored != hwid_hash_input:
        conn.close()
        log_login(key_code, hwid, False, "HWID não corresponde")
        return jsonify({"success": False, "message": "HWID não corresponde"}), 403
    
    # Verificar expiração
    if expires_at:
        expires_datetime = datetime.datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S.%f")
        if datetime.datetime.now() > expires_datetime:
            conn.close()
            log_login(key_code, hwid, False, "Chave expirada")
            return jsonify({"success": False, "message": "Chave expirada"}), 403
    
    conn.close()
    
    token = jwt.encode({"username": key_code, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, 
                      SECRET_KEY, algorithm="HS256")
    log_login(key_code, hwid, True, "Login bem-sucedido")
    return jsonify({"success": True, "message": "Login bem-sucedido", "token": token}), 200

# Função para registrar logs
def log_login(key_code, hwid, success, message):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    log_message = f"Key: {key_code}, HWID: {hwid[:8]}..., Status: {"Sucesso" if success else "Falha"}, Mensagem: {message}, Hora: {datetime.datetime.now()}"
    cursor.execute("INSERT INTO logs (log_type, message) VALUES (?, ?)", ("login", log_message))
    conn.commit()
    conn.close()

# API - Gerar chaves
@app.route("/api/keys/generate", methods=["POST"])
def generate_keys():
    data = request.json
    duration_type = data.get("duration_type")  # "hours" ou "days"
    duration_value = data.get("duration_value")
    quantity = data.get("quantity", 1)
    created_by = data.get("created_by", "unknown")
    
    if not duration_type or not duration_value:
        return jsonify({"success": False, "message": "Duração inválida"}), 400
    
    duration_hours = int(duration_value) if duration_type == "hours" else int(duration_value) * 24
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    generated_keys = []
    for _ in range(int(quantity)):
        while True:
            key_code = "bc-" + "".join([str(secrets.randbelow(10)) for _ in range(8)])
            cursor.execute("SELECT * FROM keys WHERE key_code = ?", (key_code,))
            if not cursor.fetchone():
                break
        
        cursor.execute("""
            INSERT INTO keys (key_code, duration_hours, created_by)
            VALUES (?, ?, ?)
        """, (key_code, duration_hours, created_by))
        generated_keys.append(key_code)
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "keys": generated_keys}), 200

# API - Status de chaves
@app.route("/api/keys/status", methods=["GET"])
def keys_status():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM keys")
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM keys WHERE expires_at IS NOT NULL AND expires_at < ?", 
                  (datetime.datetime.now(),))
    expired = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM keys WHERE hwid_hash IS NOT NULL")
    used = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({"success": True, "total": total, "expired": expired, "used": used}), 200

# API - Listar chaves
@app.route("/api/keys/list", methods=["GET"])
def list_keys():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT key_code, hwid_hash, is_paused, created_at, expires_at FROM keys")
    keys_data = cursor.fetchall()
    
    keys_list = []
    for key in keys_data:
        keys_list.append({
            "key_code": key[0],
            "in_use": key[1] is not None,
            "is_paused": bool(key[2]),
            "created_at": key[3],
            "expires_at": key[4]
        })
    
    conn.close()
    
    return jsonify({"success": True, "keys": keys_list}), 200

# API - Buscar chave específica
@app.route("/api/keys/search", methods=["POST"])
def search_key():
    data = request.json
    key_code = data.get("key")
    
    if not key_code:
        return jsonify({"success": False, "message": "Chave não fornecida"}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM keys WHERE key_code = ?", (key_code,))
    key_data = cursor.fetchone()
    
    conn.close()
    
    if not key_data:
        return jsonify({"success": False, "message": "Chave não encontrada"}), 404
    
    key_info = {
        "key_code": key_data[1],
        "in_use": key_data[2] is not None,
        "hwid_reset_count": key_data[3],
        "pause_count": key_data[4],
        "is_paused": bool(key_data[5]),
        "duration_hours": key_data[6],
        "created_at": key_data[7],
        "first_login_at": key_data[8],
        "expires_at": key_data[9],
        "created_by": key_data[12]
    }
    
    return jsonify({"success": True, "key_info": key_info}), 200

# API - Deletar chave
@app.route("/api/keys/delete", methods=["POST"])
def delete_key():
    data = request.json
    key_code = data.get("key")
    
    if not key_code:
        return jsonify({"success": False, "message": "Chave não fornecida"}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM keys WHERE key_code = ?", (key_code,))
    conn.commit()
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({"success": False, "message": "Chave não encontrada"}), 404
    
    conn.close()
    
    return jsonify({"success": True, "message": "Chave deletada com sucesso"}), 200

# API - Resetar todas as chaves
@app.route("/api/keys/reset-all", methods=["POST"])
def reset_all_keys():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM keys")
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Todas as chaves foram deletadas"}), 200

# API - Pausar chave
@app.route("/api/keys/pause", methods=["POST"])
def pause_key():
    data = request.json
    key_code = data.get("key")
    is_admin = data.get("is_admin", False) # Adicionado para diferenciar admin de cliente
    
    if not key_code:
        return jsonify({"success": False, "message": "Chave não fornecida"}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT pause_count, is_paused FROM keys WHERE key_code = ?", (key_code,))
    key_data = cursor.fetchone()
    
    if not key_data:
        conn.close()
        return jsonify({"success": False, "message": "Chave não encontrada"}), 404
    
    current_pause_count, is_already_paused = key_data
    
    if is_already_paused:
        conn.close()
        return jsonify({"success": False, "message": "Chave já está pausada"}), 400

    if not is_admin and current_pause_count >= 2:
        conn.close()
        return jsonify({"success": False, "message": "Limite de pausas atingido (2x)"}), 403
    
    # Incrementa pause_count apenas se não for admin e não tiver atingido o limite
    # Ou se for admin, mas ainda não tiver atingido o limite (admin pode pausar ilimitadamente, mas o contador ainda registra)
    new_pause_count = current_pause_count + 1 if not is_admin else current_pause_count # Admin não incrementa o contador de limite
    if is_admin: # Admin pode pausar ilimitadamente, mas o contador não deve ser limitado a 2
        cursor.execute("UPDATE keys SET is_paused = 1, paused_at = ? WHERE key_code = ?", 
                      (datetime.datetime.now(), key_code))
    else: # Cliente incrementa o contador
        cursor.execute("UPDATE keys SET is_paused = 1, paused_at = ?, pause_count = ? WHERE key_code = ?", 
                      (datetime.datetime.now(), new_pause_count, key_code))

    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Chave pausada com sucesso"}), 200

# API - Despausar chave
@app.route("/api/keys/unpause", methods=["POST"])
def unpause_key():
    data = request.json
    key_code = data.get("key")
    
    if not key_code:
        return jsonify({"success": False, "message": "Chave não fornecida"}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Calcular tempo pausado
    cursor.execute("SELECT paused_at, paused_duration, expires_at FROM keys WHERE key_code = ?", (key_code,))
    key_data = cursor.fetchone()
    
    if key_data and key_data[0]:
        paused_at = datetime.datetime.strptime(key_data[0], "%Y-%m-%d %H:%M:%S.%f")
        paused_duration = key_data[1] or 0
        pause_time = (datetime.datetime.now() - paused_at).total_seconds() / 3600  # em horas
        new_paused_duration = paused_duration + pause_time
        
        # Ajustar data de expiração
        if key_data[2]:
            expires_at = datetime.datetime.strptime(key_data[2], "%Y-%m-%d %H:%M:%S.%f")
            new_expires_at = expires_at + datetime.timedelta(hours=pause_time)
            
            cursor.execute("""
                UPDATE keys 
                SET is_paused = 0, paused_at = NULL, paused_duration = ?, expires_at = ?
                WHERE key_code = ?
            """, (new_paused_duration, new_expires_at, key_code))
        else:
            cursor.execute("""
                UPDATE keys 
                SET is_paused = 0, paused_at = NULL, paused_duration = ?
                WHERE key_code = ?
            """, (new_paused_duration, key_code))
    else:
        cursor.execute("UPDATE keys SET is_paused = 0 WHERE key_code = ?", (key_code,))
    
    conn.commit()
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({"success": False, "message": "Chave não encontrada"}), 404
    
    conn.close()
    
    return jsonify({"success": True, "message": "Chave despausada com sucesso"}), 200

# API - Pausar todas as chaves
@app.route("/api/keys/pause-all", methods=["POST"])
def pause_all_keys():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("UPDATE keys SET is_paused = 1, paused_at = ?", (datetime.datetime.now(),))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Todas as chaves foram pausadas"}), 200

# API - Definir duração para todas as chaves
@app.route("/api/keys/set-duration-all", methods=["POST"])
def set_duration_all():
    data = request.json
    duration_type = data.get("duration_type")
    duration_value = data.get("duration_value")
    
    if not duration_type or not duration_value:
        return jsonify({"success": False, "message": "Duração inválida"}), 400
    
    duration_hours = int(duration_value) if duration_type == "hours" else int(duration_value) * 24
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("UPDATE keys SET duration_hours = ?", (duration_hours,))
    
    # Atualizar expires_at para chaves já em uso
    cursor.execute("SELECT key_code, first_login_at FROM keys WHERE first_login_at IS NOT NULL")
    keys_in_use = cursor.fetchall()
    
    for key_code, first_login_at in keys_in_use:
        first_login = datetime.datetime.strptime(first_login_at, "%Y-%m-%d %H:%M:%S.%f")
        new_expires_at = first_login + datetime.timedelta(hours=duration_hours)
        cursor.execute("UPDATE keys SET expires_at = ? WHERE key_code = ?", (new_expires_at, key_code))
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Duração atualizada para todas as chaves"}), 200

# API - Definir duração para chave específica
@app.route("/api/keys/set-duration", methods=["POST"])
def set_duration_specific():
    data = request.json
    key_code = data.get("key")
    duration_type = data.get("duration_type")
    duration_value = data.get("duration_value")
    
    if not key_code or not duration_type or not duration_value:
        return jsonify({"success": False, "message": "Parâmetros inválidos"}), 400
    
    duration_hours = int(duration_value) if duration_type == "hours" else int(duration_value) * 24
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT first_login_at FROM keys WHERE key_code = ?", (key_code,))
    key_data = cursor.fetchone()
    
    if not key_data:
        conn.close()
        return jsonify({"success": False, "message": "Chave não encontrada"}), 404
    
    cursor.execute("UPDATE keys SET duration_hours = ? WHERE key_code = ?", (duration_hours, key_code))
    
    # Se a chave já está em uso, atualizar expires_at
    if key_data[0]:
        first_login = datetime.datetime.strptime(key_data[0], "%Y-%m-%d %H:%M:%S.%f")
        new_expires_at = first_login + datetime.timedelta(hours=duration_hours)
        cursor.execute("UPDATE keys SET expires_at = ? WHERE key_code = ?", (new_expires_at, key_code))
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Duração atualizada para a chave"}), 200

# API - Limpar chaves expiradas
@app.route("/api/keys/clean-expired", methods=["POST"])
def clean_expired_keys():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM keys WHERE expires_at IS NOT NULL AND expires_at < ?", 
                  (datetime.datetime.now(),))
    deleted_count = cursor.rowcount
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": f"{deleted_count} chaves expiradas foram deletadas"}), 200

# API - Resetar HWID
@app.route("/api/keys/reset-hwid", methods=["POST"])
def reset_hwid():
    data = request.json
    key_code = data.get("key")
    is_admin = data.get("is_admin", False)
    
    if not key_code:
        return jsonify({"success": False, "message": "Chave não fornecida"}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT hwid_reset_count FROM keys WHERE key_code = ?", (key_code,))
    key_data = cursor.fetchone()
    
    if not key_data:
        conn.close()
        return jsonify({"success": False, "message": "Chave não encontrada"}), 404
    
    reset_count = key_data[0]
    
    if not is_admin and reset_count >= 3:
        conn.close()
        return jsonify({"success": False, "message": "Limite de resets atingido (3x)"}), 403
    
    cursor.execute("""
        UPDATE keys 
        SET hwid_hash = NULL, hwid_reset_count = hwid_reset_count + 1, 
            first_login_at = NULL, expires_at = NULL
        WHERE key_code = ?
    """, (key_code,))
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "HWID resetado com sucesso"}), 200

# API - Gerenciar permissões
@app.route("/api/permissions/grant", methods=["POST"])
def grant_permission():
    data = request.json
    user_id = data.get("user_id")
    permission_type = data.get("permission_type")  # "all_commands" ou "generate_keys"
    
    if not user_id or not permission_type:
        return jsonify({"success": False, "message": "Parâmetros inválidos"}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    if permission_type == "all_commands":
        cursor.execute("""
            INSERT INTO permissions (user_id, can_use_all_commands)
            VALUES (?, 1)
            ON CONFLICT(user_id) DO UPDATE SET can_use_all_commands = 1
        """, (user_id,))
    elif permission_type == "generate_keys":
        cursor.execute("""
            INSERT INTO permissions (user_id, can_generate_keys)
            VALUES (?, 1)
            ON CONFLICT(user_id) DO UPDATE SET can_generate_keys = 1
        """, (user_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Permissão concedida"}), 200

# API - Remover permissões
@app.route("/api/permissions/revoke", methods=["POST"])
def revoke_permission():
    data = request.json
    user_id = data.get("user_id")
    
    if not user_id:
        return jsonify({"success": False, "message": "User ID não fornecido"}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM permissions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Permissões removidas"}), 200

# API - Listar permissões
@app.route("/api/permissions/list", methods=["GET"])
def list_permissions():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT user_id, can_use_all_commands, can_generate_keys FROM permissions")
    permissions_data = cursor.fetchall()
    
    permissions_list = []
    for perm in permissions_data:
        permissions_list.append({
            "user_id": perm[0],
            "can_use_all_commands": bool(perm[1]),
            "can_generate_keys": bool(perm[2])
        })
    
    conn.close()
    
    return jsonify({"success": True, "permissions": permissions_list}), 200

# API - Verificar permissão
@app.route("/api/permissions/check", methods=["POST"])
def check_permission():
    data = request.json
    user_id = data.get("user_id")
    permission_type = data.get("permission_type")
    
    if not user_id or not permission_type:
        return jsonify({"success": False, "message": "Parâmetros inválidos"}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT can_use_all_commands, can_generate_keys FROM permissions WHERE user_id = ?", (user_id,))
    perm_data = cursor.fetchone()
    
    conn.close()
    
    if not perm_data:
        return jsonify({"success": True, "has_permission": False}), 200
    
    if permission_type == "all_commands":
        has_perm = bool(perm_data[0])
    elif permission_type == "generate_keys":
        has_perm = bool(perm_data[1])
    else:
        has_perm = False
    
    return jsonify({"success": True, "has_permission": has_perm}), 200

# API - Obter logs
@app.route("/api/logs", methods=["GET"])
def get_logs():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT log_type, message, created_at FROM logs ORDER BY created_at DESC LIMIT 100")
    logs_data = cursor.fetchall()
    
    logs_list = []
    for log in logs_data:
        logs_list.append({
            "log_type": log[0],
            "message": log[1],
            "created_at": log[2]
        })
    
    conn.close()
    
    return jsonify({"success": True, "logs": logs_list}), 200

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)

