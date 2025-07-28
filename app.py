import os
import time
import jwt
import requests
import psycopg2
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt

# --- KONFIGURACJA ---
load_dotenv()

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET')
DATABASE_URL = os.environ.get('DATABASE_URL')
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL')
COOLDOWN_MINUTES = 15
REDEEM_COST = 10000

# --- POŁĄCZENIE Z BAZĄ DANYCH ---
def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# --- NOWA FUNKCJA: AUTOMATYCZNA INICJALIZACJA BAZY DANYCH ---
def init_db():
    """Tworzy tabelę users, jeśli nie istnieje."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            points INTEGER DEFAULT 0,
            last_spin_timestamp BIGINT DEFAULT 0
        );
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("Database initialized.")

# --- DEKORATOR DO AUTORYZACJI ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Nieprawidłowy format tokenu Bearer'}), 401


        if not token:
            return jsonify({'message': 'Brak tokenu!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']
        except Exception as e:
            return jsonify({'message': 'Token jest nieprawidłowy!'}), 401

        return f(current_user_id, *args, **kwargs)
    return decorated

# --- ENDPOINTY API ---

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Brakuje nazwy użytkownika lub hasła'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
            (username, hashed_password)
        )
        conn.commit()
    except psycopg2.IntegrityError:
        return jsonify({'message': 'Użytkownik o tej nazwie już istnieje'}), 409
    finally:
        cur.close()
        conn.close()

    return jsonify({'message': 'Użytkownik zarejestrowany pomyślnie'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Błąd logowania'}), 401

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user and bcrypt.check_password_hash(user[1], password):
        token = jwt.encode(
            {'user_id': user[0], 'exp': int(time.time()) + 86400}, # Token ważny 24h
            app.config['SECRET_KEY'],
            algorithm="HS256"
        )
        return jsonify({'token': token})

    return jsonify({'message': 'Nieprawidłowe dane logowania'}), 401

@app.route('/api/user/data', methods=['GET'])
@token_required
def get_user_data(current_user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username, points, last_spin_timestamp FROM users WHERE id = %s", (current_user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        return jsonify({'message': 'Nie znaleziono użytkownika'}), 404

    return jsonify({
        'username': user[0],
        'points': user[1],
        'last_spin_timestamp': user[2]
    })

@app.route('/api/spin', methods=['POST'])
@token_required
def spin(current_user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT points, last_spin_timestamp FROM users WHERE id = %s", (current_user_id,))
    user = cur.fetchone()
    
    now = int(time.time() * 1000)
    cooldown_end = user[1] + (COOLDOWN_MINUTES * 60 * 1000)

    if now < cooldown_end:
        cur.close()
        conn.close()
        return jsonify({'message': 'Musisz jeszcze poczekać'}), 429

    points_won = int(time.time()) % 100 + 5 # Proste losowanie 5-104
    new_points = user[0] + points_won

    cur.execute(
        "UPDATE users SET points = %s, last_spin_timestamp = %s WHERE id = %s",
        (new_points, now, current_user_id)
    )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'message': f'Wygrałeś {points_won} punktów!', 'new_points': new_points, 'last_spin_timestamp': now})

@app.route('/api/redeem', methods=['POST'])
@token_required
def redeem(current_user_id):
    data = request.get_json()
    roblox_username = data.get('robloxUsername')
    gamepass_id = data.get('gamepassId')

    if not roblox_username or not gamepass_id:
        return jsonify({'message': 'Brakujące dane'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT points, username FROM users WHERE id = %s", (current_user_id,))
    user = cur.fetchone()

    if user[0] < REDEEM_COST:
        cur.close()
        conn.close()
        return jsonify({'message': 'Niewystarczająca ilość punktów'}), 403

    new_points = user[0] - REDEEM_COST
    cur.execute("UPDATE users SET points = %s WHERE id = %s", (new_points, current_user_id))
    conn.commit()
    
    # Wysyłanie powiadomienia na Discord
    if DISCORD_WEBHOOK_URL:
        discord_payload = {
            "embeds": [{
                "title": "Nowa prośba o wymianę punktów!",
                "color": 5814783,
                "fields": [
                    {"name": "Użytkownik Strony", "value": user[1]},
                    {"name": "Użytkownik Roblox", "value": roblox_username, "inline": True},
                    {"name": "ID Game Passa", "value": gamepass_id, "inline": True}
                ]
            }]
        }
        try:
            requests.post(DISCORD_WEBHOOK_URL, json=discord_payload)
        except Exception as e:
            print(f"Błąd wysyłania webhooka: {e}")

    cur.close()
    conn.close()
    return jsonify({'message': 'Prośba o wymianę została wysłana!'})

# --- URUCHOMIENIE APLIKACJI ---
if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

