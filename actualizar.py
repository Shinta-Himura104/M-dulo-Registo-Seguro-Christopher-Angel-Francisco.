from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import jwt # <-- Nueva importación
import datetime # <-- Nueva importación para la expiración del token

app = Flask(__name__)

# Configuramos una clave secreta para firmar los JWT. 
# En un entorno real, esto debería ser una variable de entorno muy segura.
app.config['SECRET_KEY'] = 'mi_clave_secreta_universitaria_123'

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row 
    return conn

# ... [Tus rutas de /registro y /actualizar se quedan exactamente igual] ...

@app.route('/login', methods=['POST'])
def login():
    datos = request.get_json()
    
    email = datos.get('email')
    password = datos.get('password')

    if not email or not password:
        return jsonify({"error": "Faltan datos"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Buscamos al usuario por email
    usuario = cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()
    conn.close()

    if not usuario:
        return jsonify({"mensaje": "Usuario no encontrado"}), 404

    # Verificamos la contraseña contra el hash almacenado en la BD
    password_planas = password.encode('utf-8')
    password_hasheada = usuario['password']

    if bcrypt.checkpw(password_planas, password_hasheada):
        # Si es exitoso, generamos el JWT
        # El Payload NO debe contener contraseñas, solo identificadores
        payload = {
            'id': usuario['id'],
            'email': usuario['email'],
            'role': usuario['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2) # El token expira en 2 horas
        }
        
        # Firmamos el token con nuestra clave secreta
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            "mensaje": "Login exitoso",
            "token": token
        }), 200
    else:
        return jsonify({"mensaje": "Credenciales Invalidas"}), 401

if __name__ == '__main__':
    app.run(debug=True, port=5000)