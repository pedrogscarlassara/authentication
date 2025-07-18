from flask import Flask, request, render_template
from dotenv import load_dotenv
from datetime import datetime
import requests
import hashlib
import sqlite3
import bcrypt
import jwt
import os

# cliente e servidor estão gerando a mesma senha

load_dotenv()
app = Flask(__name__)

def get_user_ip():
   response = requests.get('https://api.ipify.org', headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15'})
   return response

def get_user_agent():
    return request.headers.get('User-Agent')

def verify_user_agent():
    if request.headers.get('User-Agent') == 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0':
        return True
    else:
        return False

@app.route('/')
def main():
    requests.post(
        'https://discord.com/api/webhooks/1395438211307671582/CMaG4AMpLiCbgmZ2IQfJ6ZQK00t6dkwQAV7PPpccbWDm_4CZCaWDKed5sjxrG4HBRFMm',
        json={'content': f'Someone connected to the Main endpoint.\nUser-Agent: || {get_user_agent()} ||', 'username': 'Main Endpoint'})
    if verify_user_agent():
        return render_template('main.html'), 200
    else:
        return render_template('main.html'), 200

@app.route('/register/<string:username>/<string:password>')
def register(username, password):
    encode = jwt.encode({"key": f"{username}{password}{get_user_ip()}"}, os.getenv("SECRET_KEY"), algorithm='HS256')
    print(f'Encoded: {encode}')

    requests.post(
        'https://discord.com/api/webhooks/1395438211307671582/CMaG4AMpLiCbgmZ2IQfJ6ZQK00t6dkwQAV7PPpccbWDm_4CZCaWDKed5sjxrG4HBRFMm',
        json={'content': f'Someone connected to the Register endpoint.\nUser-Agent: || {get_user_agent()} ||\nArguments:\n\t{username}\n\t{password}', 'username': 'Register Endpoint'})

    if verify_user_agent():
        con = sqlite3.connect('test.db')
        cur = con.cursor()
        cur.execute('INSERT INTO customers (username, password, token) VALUES (?, ?, ?)',
                    (username, password, 'token_exemplo'))
        con.commit()
        con.close()

        return render_template('register.html'), 200
    else:
        return render_template('register.html'), 200

app.run(debug=True)