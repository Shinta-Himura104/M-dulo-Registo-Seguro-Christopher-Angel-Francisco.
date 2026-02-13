import requests

# URL de tu servidor local
url = "http://127.0.0.1:5000/registro"

# 1. Prueba de Éxito (Debe decir "Usuario Registrado")
datos_bien = {"email": "alumno@test.com", "password": "123456789"}
respuesta = requests.post(url, json=datos_bien)
print(f"Intento Correcto: {respuesta.status_code} - {respuesta.json()}")

# 2. Prueba de Error (Debe decir "Credenciales Invalidas")
datos_mal = {"email": "mal@test.com", "password": "123"} 
respuesta = requests.post(url, json=datos_mal)
print(f"Intento Password Corta: {respuesta.status_code} - {respuesta.json()}")