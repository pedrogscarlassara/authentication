from flask import Flask, request, render_template, jsonify
from dotenv import load_dotenv
from datetime import datetime, timezone
import requests
import hashlib
import sqlite3
import bcrypt
import jwt
import os

load_dotenv()
app = Flask(__name__)

def get_user_agent():
    return request.headers.get('User-Agent')

def get_user_ip():
    response = requests.get('http://127.0.0.1:5000/ip')
    return response.json()['ip']

def verify_user_agent():
    if request.headers.get('User-Agent') == 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0':
        return True
    else:
        return False

@app.route('/')
def main():
    requests.post(
        os.getenv("DISCORD_WEBHOOK"),
        json={'content': f'Someone connected to the Main endpoint.\nUser-Agent: || {get_user_agent()} ||', 'username': 'Main Endpoint'})
    if verify_user_agent():
        return render_template('main.html'), 200
    else:
        return render_template('main.html'), 200

@app.route('/register/<string:username>/<string:password>/<string:token>')
def register(username, password, token):
    #verificar expiry do token
    encode = jwt.encode({"key": f"{username}{password}{get_user_ip()}", 'exp': datetime.now(tz=timezone.utc)}, os.getenv("SECRET_KEY"), algorithm='HS256', headers={'secret': os.getenv("HEADER_KEY")})
    print(f'Token: {token}')
    print(f'Encode: {encode}')

    requests.post(
        os.getenv("DISCORD_WEBHOOK"),
        json={'content': f'Someone connected to the Register endpoint.\nUser-Agent: || {get_user_agent()} ||\nArguments:\n\t{username}\n\t{password}', 'username': 'Register Endpoint'})

    if verify_user_agent() and token == encode:
        con = sqlite3.connect('test.db')
        cur = con.cursor()
        cur.execute('INSERT INTO customers (username, password, token) VALUES (?, ?, ?)',
                    (username, password, 'token_exemplo'))
        con.commit()
        con.close()

        return render_template('register.html'), 200
    else:
        return render_template('register.html'), 200

@app.route('/ip')
def ip():
    if verify_user_agent():
        return jsonify({'ip': f'{request.remote_addr}'}), 200
    else:
        return jsonify({'ip': f'{request.remote_addr}'}), 200

app.run(debug=True)