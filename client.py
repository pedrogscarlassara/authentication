import requests
import bcrypt
import jwt
import os
from dotenv import load_dotenv


load_dotenv()

def get_user_ip():
   response = requests.get('http://127.0.0.1:5000/ip', headers={'User-Agent': f'{os.getenv('IP_USER_AGENT')}'})
   print(response.text)
   return response.json()['ip']

username = 'pedro'
non_encrypted_password = b'password'
password = bcrypt.hashpw(non_encrypted_password, bcrypt.gensalt(8))

encode = jwt.encode({"key": f"{username}{password}{get_user_ip()}"}, os.getenv("SECRET_KEY"), algorithm='HS256',headers={'secret': 'register'})

debug = requests.get(f'http://127.0.0.1:5000/register/{username}/{password}/{encode}', headers={'User-Agent': f'register'})
print(debug.status_code)
print(debug.text)
