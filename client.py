from dotenv import load_dotenv
from datetime import datetime, timezone
import jwt
import os
import requests

username = 'pedro'
password = 'senha'

load_dotenv()

def get_user_ip():
   response = requests.get('http://127.0.0.1:5000/ip', headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0'})
   return response.json()['ip']

def register():
   encode = jwt.encode({"key": f"{username}{password}{get_user_ip()}", 'exp': datetime.now(tz=timezone.utc)}, os.getenv("SECRET_KEY"), algorithm='HS256', headers={'secret': os.getenv("HEADER_KEY")})
   response = requests.get(f'http://127.0.0.1:5000/register/{username}/{password}/{encode}')
   print(response.status_code)

   print(f'Debug: {encode}')

register()

