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

def verify_user_agent(agent):
    if request.headers.get('User-Agent') == os.getenv(agent):
        return True
    else:
        return False

@app.route('/')
def main():
    requests.post(
        os.getenv("DISCORD_WEBHOOK"),
        json={'content': f'Someone connected to the Main endpoint.\nUser-Agent: || {get_user_agent()} ||', 'username': 'Main Endpoint'})
    return render_template('main.html'), 200

@app.route('/register/<string:username>/<string:password>/<string:token>')
def register(username, password, token):
    encode = jwt.encode({"key": f"{username}{password}{get_user_ip()}"}, os.getenv("SECRET_KEY"), algorithm='HS256', headers={'secret': os.getenv("REGISTER_USER_AGENT")})

    requests.post(
        os.getenv("DISCORD_WEBHOOK"),
        json={'content': f'Someone connected to the Register endpoint.\nUser-Agent: || {get_user_agent()} ||\nArguments:\n\t{username}\n\t{password}', 'username': 'Register Endpoint'})

    print(f'Debug: {get_user_agent()}')
    if verify_user_agent(os.getenv("REGISTER_USER_AGENT")) and token == encode:
        print('oi')
        con = sqlite3.connect(os.getenv("DATABASE_FILE_NAME"))
        cur = con.cursor()
        cur.execute('INSERT INTO customers (username, password) VALUES (?, ?)',
                    (username, password)) #lembrar de encriptar senha com argon2 ou bcrypt
        con.commit()
        con.close()

        return render_template('register.html'), 200
    else:
        return render_template('error.html'), 404

@app.route('/login/<string:username>/<string:password>/<string:token>')
def login(username, password, token):
    encode = jwt.encode({"key": f"{username}{password}{get_user_ip()}"}, os.getenv("SECRET_KEY"), algorithm='HS256', headers={'secret': os.getenv("LOGIN_USER_AGENT")})
    requests.post(
        os.getenv("DISCORD_WEBHOOK"),
        json={'content': f'Someone connected to the Login endpoint.\nUser-Agent: || {get_user_agent()} ||', 'username': 'Login Endpoint'})

    if verify_user_agent("LOGIN_USER_AGENT") and token == encode:
        con = sqlite3.connect(os.getenv("DATABASE_FILE_NAME"))
        cur = con.cursor()
        cur.execute("SELECT * FROM customers WHERE username = ?", (username,))
        con.commit()
        con.close()
        return render_template('login.html'), 200
    else:
        return render_template('error.html'), 404

@app.route('/delete/<string:username>/<string:password>/<string:token>')
def delete(username, password, token):
    encode = jwt.encode({"key": f"{username}{password}{get_user_ip()}"}, os.getenv("SECRET_KEY"), algorithm='HS256', headers={'secret': os.getenv("DELETE_USER_AGENT")})
    requests.post(
        os.getenv("DISCORD_WEBHOOK"),
        json={'content': f'Someone connected to the Delete endpoint.\nUser-Agent: || {get_user_agent()} ||', 'username': 'Delete Endpoint'})
    if verify_user_agent("DELETE_USER_AGENT") and token == encode:
        con = sqlite3.connect(os.getenv("DATABASE_FILE_NAME"))
        cur = con.cursor()
        cur.execute("DELETE FROM customers WHERE username = ? AND password = ?", (username, password))
        con.commit()
        con.close()
        return render_template('delete.html'), 200
    else:
        return render_template('error.html'), 404

@app.route('/ip')
def ip():
    requests.post(
        os.getenv("DISCORD_WEBHOOK"),
        json={'content': f'Someone connected to the IP endpoint.\nUser-Agent: || {get_user_agent()} ||', 'username': 'IP Endpoint'})
    if verify_user_agent(os.getenv("IP_USER_AGENT")):
        return jsonify({'ip': f'{request.remote_addr}'}), 200
    else:
        return render_template(), 404

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html'), 404

app.run(debug=True)