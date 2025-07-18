# Arquivo para emular o lado do cliente
from dotenv import load_dotenv
import jwt
import os
import requests

username = 'pedro'
password = 'senha'

# cliente e servidor estão gerando a mesma senha


load_dotenv()
def get_user_ip():
   response = requests.get('https://api.ipify.org', headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15'})
   return response


encode = jwt.encode({"key": f"{username}{password}{get_user_ip()}"}, os.getenv("SECRET_KEY"), algorithm='HS256')
print(encode)
