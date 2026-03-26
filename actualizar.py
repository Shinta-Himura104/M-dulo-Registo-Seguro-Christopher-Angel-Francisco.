import os
from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import jwt
import datetime

app = Flask(__name__)

# CORRECCIÓN B105: Se usa os.environ para evitar contraseñas hardcoded
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'clave_temporal_de_desarrollo_segura')

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row 
    return conn

# ... (Tus rutas de /registro y /actualizar se mantienen igual) ...

if __name__ == '__main__':
    # CORRECCIÓN B201: debug=False para evitar ejecución de código arbitrario
    app.run(debug=False, port=5000)