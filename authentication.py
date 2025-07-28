from flask import Flask, request, render_template, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timezone
from dotenv import load_dotenv
import requests
import sqlite3
import bcrypt
import jwt
import os

load_dotenv()
app = Flask(__name__)

limiter = Limiter(app=app, key_func=get_remote_address, storage_uri="memory://")

def get_user_agent():
    return request.headers.get('User-Agent')

def get_user_ip():
    response = requests.get('http://127.0.0.1:5000/ip', headers={'User-Agent': f'{os.getenv("IP_USER_AGENT")}'})
    return response.json()['ip']

def verify_user_agent(agent):
    return request.headers.get('User-Agent') == agent

def verify_jwt_token(token, expected_secret):
    try:
        decoded = jwt.decode(
            token,
            os.getenv("SECRET_KEY"),
            algorithms=['HS256'],
            options={'verify_exp': True}
        )
        headers = jwt.get_unverified_header(token)
        if headers.get('secret') != expected_secret:
            print(f"Header secret mismatch: expected {expected_secret}, got {headers.get('secret')}")
            return False
        return decoded
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return False
    except jwt.InvalidTokenError as e:
        print(f"Invalid token error: {e}")
        return False

def discord_webhook(message, username):
    requests.post(
        os.getenv("DISCORD_WEBHOOK"),
        json={'content': f'{message}\nUser-Agent: {get_user_agent()}\nIP: {get_user_ip()}',
              'username': username})

@app.route('/')
def main():
    #discord_webhook('Someone connected to the Main endpoint', 'Main Endpoint')
    return render_template('main.html'), 200

@app.route('/register/<string:username>/<string:password>/<string:token>')
@limiter.limit('5/minute')
def register(username, password, token):
    decoded = verify_jwt_token(token, 'register')
    if not decoded:
        discord_webhook('Unable to decode JWT token', 'Register Endpoint')
        return render_template('error.html'), 401

    discord_webhook('Someone connected to the Register endpoint', 'Register Endpoint')

    if verify_user_agent(os.getenv("REGISTER_USER_AGENT")):
        discord_webhook('Registering a user to the database', 'Register Endpoint')
        con = sqlite3.connect(os.getenv("DATABASE_FILE_NAME"))
        cur = con.cursor()
        try:
            bcrypt.checkpw(b"test", password.encode('utf-8'))
            hashed_password = password.encode('utf-8')
        except ValueError:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cur.execute('INSERT INTO customers (username, password) VALUES (?, ?)', (username, hashed_password))
        cur.execute('INSERT INTO analytics (event, ip, useragent, timestamp) VALUES (?, ?, ?, ?)',
                    (f'Registered a user: {username}', get_user_ip(), get_user_agent(), datetime.now()))
        con.commit()
        discord_webhook('Registered a user to the database', 'Register Endpoint')
        con.close()
        return render_template('register.html'), 200
    else:
        discord_webhook('Invalid user agent', 'Register Endpoint')
        return render_template('error.html'), 401

@app.route('/login/<string:username>/<string:password>/<string:token>')
@limiter.limit('5/minute')
def login(username, password, token):
    decoded = verify_jwt_token(token, os.getenv("LOGIN_USER_AGENT"))
    if not decoded:
        discord_webhook('Unable to decode JWT token', 'Login Endpoint')
        return render_template('error.html'), 401

    discord_webhook('Someone connected to the Login endpoint', 'Login Endpoint')

    if verify_user_agent(os.getenv("LOGIN_USER_AGENT")):
        con = sqlite3.connect(os.getenv("DATABASE_FILE_NAME"))
        cur = con.cursor()
        cur.execute("SELECT password FROM customers WHERE username = ?", (username,))
        result = cur.fetchone()
        con.close()

        if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
            new_token = jwt.encode(
                {
                    "key": f"{username}{password}{get_user_ip()}",
                    "exp": datetime.now(timezone.utc).timestamp() + 3600,
                    "headers": {"secret": os.getenv("LOGIN_USER_AGENT")}
                },
                os.getenv("SECRET_KEY"),
                algorithm='HS256'
            )
            return jsonify({'token': new_token, 'message': 'Login successful'}), 200
        else:
            discord_webhook('Invalid credentials', 'Login Endpoint')
            return render_template('error.html'), 401
    else:
        discord_webhook('Invalid user agent', 'Login Endpoint')
        print(f"User-Agent: {get_user_agent()}")
        return render_template('error.html'), 401

@app.route('/delete/<string:username>/<string:password>/<string:token>')
@limiter.limit('5/minute')
def delete(username, password, token):
    decoded = verify_jwt_token(token, os.getenv("DELETE_USER_AGENT"))
    if not decoded:
        discord_webhook('Unable to decode JWT token', 'Delete Endpoint')
        return render_template('error.html'), 401

    discord_webhook('Someone connected to the Delete endpoint', 'Delete Endpoint')
    if verify_user_agent(os.getenv("DELETE_USER_AGENT")):
        con = sqlite3.connect(os.getenv("DATABASE_FILE_NAME"))
        cur = con.cursor()
        cur.execute("SELECT password FROM customers WHERE username = ?", (username,))
        result = cur.fetchone()

        if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
            cur.execute("DELETE FROM customers WHERE username = ?", (username,))
            cur.execute('INSERT INTO analytics (event, ip, useragent, timestamp) VALUES (?, ?, ?, ?)',
                        (f'Deleted a user: {username}', get_user_ip(), get_user_agent(), datetime.now()))
            con.commit()
            discord_webhook(f'Deleted {username} from the database', 'Delete Endpoint')
            con.close()
            return render_template('delete.html'), 200
        else:
            con.close()
            discord_webhook('Invalid credentials', 'Delete Endpoint')
            return render_template('error.html'), 401
    else:
        discord_webhook('Invalid user agent', 'Delete Endpoint')
        return render_template('error.html'), 401

@app.route('/ip')
@limiter.limit('5/minute')
def ip():
    if verify_user_agent(os.getenv("IP_USER_AGENT")):
        return jsonify({'ip': f'{request.remote_addr}'}), 200
    else:
        discord_webhook('Invalid user agent', 'IP Endpoint')
        return render_template('error.html'), 401

@app.route('/analytics')
def analytics():
    # Private visualizer for logs
    con = sqlite3.connect(os.getenv("DATABASE_FILE_NAME"))
    cur = con.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS analytics(event TEXT, ip TEXT, useragent TEXT, timestamp DATETIME)')
    con.close()
    return ''

@app.errorhandler(404)
def page_not_found(e):
    discord_webhook('Page not found', 'Error Handler')
    return render_template('error.html'), 404

if __name__ == '__main__':
    app.run(debug=True)