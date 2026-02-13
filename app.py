from flask import Flask, request, jsonify
import sqlite3
import bcrypt

app = Flask(__name__)

# --- Función auxiliar para conectarse a la BD ---
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row # Esto ayuda a manejar los datos mejor
    return conn

# --- ENDPOINT: /registro (POST) ---
@app.route('/registro', methods=['POST'])
def registro():
    datos = request.get_json()
    
    # 1. Obtenemos datos del JSON
    email = datos.get('email')
    password = datos.get('password')

    # 2. VALIDACIÓN DE ENTRADA
    # Instrucción: "la contraseña debe ser mayor a 8 caracteres y menor a 10"
    # Esto significa estrictamente que la longitud debe ser 9.
    if not email or not password:
        return jsonify({"error": "Faltan datos"}), 400

    largo_pass = len(password)
    if not (largo_pass > 8 and largo_pass < 10):
        # Retornamos Error 400 si no cumple la longitud
        return jsonify({"mensaje": "Credenciales Invalidas"}), 400

    # 3. VERIFICAR DUPLICADOS
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Buscamos si el email ya existe
    usuario_existente = cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()

    if usuario_existente:
        conn.close()
        # Retornamos Error 409 si ya existe
        return jsonify({"mensaje": "El usuario ya existe"}), 409

    # 4. HASH DE LA CONTRASEÑA (BCRYPT)
    # Convertimos la password a bytes y generamos el hash
    bytes_password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(bytes_password, salt)

    # 5. GUARDAR EN LA BASE DE DATOS
    try:
        # Insertamos email y el hash (NO la contraseña plana)
        # No insertamos 'role' para que SQL use el DEFAULT 'cliente'
        cursor.execute('INSERT INTO usuarios (email, password) VALUES (?, ?)', 
                       (email, hashed_password))
        conn.commit()
        conn.close()

        # 6. MENSAJE DE ÉXITO
        return jsonify({"mensaje": "Usuario Registrado"}), 201

    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)