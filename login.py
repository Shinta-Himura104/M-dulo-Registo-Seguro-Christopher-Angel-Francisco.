import requests

url = "http://127.0.0.1:5000/login"

datos_login = {
    "email": "morrigan@usuario.com", 
    "password": "987654321"
}

try:
    respuesta = requests.post(url, json=datos_login)
    
    if respuesta.status_code == 200:
        data = respuesta.json()
        print(f"Éxito: {data.get('mensaje')}")
        print(f"Tu JWT es: {data.get('token')}") # <-- Imprimimos el token
    else:
        print(f"Error {respuesta.status_code}")
        print(f"Contenido de la respuesta: {respuesta.text}") 

except Exception as e:
    print(f"Error de conexión: {e}")    