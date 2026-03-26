import requests
import os

url = "http://127.0.0.1:5000/login"

# Se recomienda no dejar credenciales en el script, o cargarlas de variables de entorno
user_email = os.environ.get("TEST_USER", "morrigan@usuario.com")
user_pass = os.environ.get("TEST_PASS", "987654321")

datos_login = {
    "email": user_email,
    "password": user_pass
}

try:
    # CORRECCIÓN B113: Se agrega timeout para evitar cuelgues infinitos
    respuesta = requests.post(url, json=datos_login, timeout=5)
    
    if respuesta.status_code == 200:
        data = respuesta.json()
        print(f"Éxito: Token generado.")
        print(f"Tu JWT es: {data.get('token')}")
    else:
        print(f"Error {respuesta.status_code}: {respuesta.text}")

except requests.exceptions.Timeout:
    print("Error: La petición expiró (Timeout)")
except Exception as e:
    print(f"Error de conexión: {e}")