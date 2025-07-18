from dotenv import load_dotenv
from datetime import datetime, timezone
import jwt
import os
import requests

username = ''
password = ''

load_dotenv()

def get_user_ip():
   response = requests.get('http://127.0.0.1:5000/ip', headers={'User-Agent': f'{os.getenv("USER_AGENT")}'})
   return response.json()['ip']

def register():
   encode = jwt.encode({"key": f"{username}{password}{get_user_ip()}"}, os.getenv("SECRET_KEY"), algorithm='HS256', headers={'secret': os.getenv("HEADER_KEY")})
   response = requests.get(f'http://127.0.0.1:5000/delete/{username}/{password}/{encode}', headers={'User-Agent': f'{os.getenv("USER_AGENT")}'})
   print(response.status_code)

   print(f'Debug: {encode}')

register()

