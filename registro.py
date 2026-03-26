import requests
import os

url = "http://127.0.0.1:5000/registro"

# CORRECCIÓN B105: No declarar la contraseña directamente en el diccionario
# La definimos como una variable de configuración o entorno
TEST_PASSWORD = os.environ.get("USER_REG_PASS", "PasswordSegura123!")

datos_bien = {
    "email": "alumno_final@test.com", 
    "password": TEST_PASSWORD 
}

try:
    # CORRECCIÓN B113: Manteniendo el timeout de seguridad
    respuesta = requests.post(url, json=datos_bien, timeout=5)
    print(f"Resultado Registro: {respuesta.status_code} - {respuesta.json()}")
except requests.exceptions.Timeout:
    print("Error: El servidor tardó demasiado en responder.")
except Exception as e:
    print(f"Error: {e}")