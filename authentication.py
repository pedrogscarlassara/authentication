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

#criar user-agent diferente pra cada endpoint, assim aumenta o salt do encode

def get_user_agent():
    return request.headers.get('User-Agent')

def get_user_ip():
    #usando ip local por enquanto, mudar dps
    response = requests.get('http://127.0.0.1:5000/ip')
    return response.json()['ip']

def verify_user_agent():
    if request.headers.get('User-Agent') == os.getenv("USER_AGENT"):
        return True
    else:
        return False

# por enquanto apenas um placeholder
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
    encode = jwt.encode({"key": f"{username}{password}{get_user_ip()}"}, os.getenv("SECRET_KEY"), algorithm='HS256', headers={'secret': os.getenv("HEADER_KEY")})

    requests.post(
        os.getenv("DISCORD_WEBHOOK"),
        json={'content': f'Someone connected to the Register endpoint.\nUser-Agent: || {get_user_agent()} ||\nArguments:\n\t{username}\n\t{password}', 'username': 'Register Endpoint'})

    print(f'Debug: {get_user_agent()}')
    if verify_user_agent() and token == encode:
        print('oi')
        con = sqlite3.connect(os.getenv("DATABASE_FILE_NAME"))
        cur = con.cursor()
        cur.execute('INSERT INTO customers (username, password) VALUES (?, ?)',
                    (username, password)) #lembrar de encriptar senha com argon2 ou bcrypt
        con.commit()
        con.close()

        return render_template('register.html'), 200
    else:
        return render_template('register.html'), 200

@app.route('/login/<string:username>/<string:password>/<string:token>')
def login(username, password, token):
    encode = jwt.encode({"key": f"{username}{password}{get_user_ip()}"}, os.getenv("SECRET_KEY"), algorithm='HS256', headers={'secret': os.getenv("HEADER_KEY")})

    print(get_user_agent())
    print(token)
    print(encode)
    if verify_user_agent() and token == encode:
        con = sqlite3.connect(os.getenv("DATABASE_FILE_NAME"))
        cur = con.cursor()
        cur.execute("SELECT * FROM customers WHERE username = ?", (username,))
        con.commit()
        con.close()
        return render_template('login.html'), 200
    else:
        return render_template('login.html'), 200

@app.route('/delete/<string:username>/<string:password>/<string:token>')
def delete(username, password, token):
    encode = jwt.encode({"key": f"{username}{password}{get_user_ip()}"}, os.getenv("SECRET_KEY"), algorithm='HS256', headers={'secret': os.getenv("HEADER_KEY")})
    if verify_user_agent() and token == encode:
        con = sqlite3.connect(os.getenv("DATABASE_FILE_NAME"))
        cur = con.cursor()
        cur.execute("DELETE FROM customers WHERE username = ? AND password = ?", (username, password))
        con.commit()
        con.close()
        return 'holder'
    else:
        return 'holder'

@app.route('/ip')
def ip():
    if verify_user_agent():
        return jsonify({'ip': f'{request.remote_addr}'}), 200
    else:
        return jsonify({'ip': f'{request.remote_addr}'}), 200

app.run(debug=True)