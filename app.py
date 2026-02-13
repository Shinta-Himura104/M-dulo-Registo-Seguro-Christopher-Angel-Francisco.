from flask import Flask, request, jsonify
import sqlite3
import bcrypt

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row 
    return conn

@app.route('/registro', methods=['POST'])
def registro():
    datos = request.get_json()
    
    email = datos.get('email')
    password = datos.get('password')


    if not email or not password:
        return jsonify({"error": "Faltan datos"}), 400

    largo_pass = len(password)
    if not (largo_pass > 8 and largo_pass < 10):
        return jsonify({"mensaje": "Credenciales Invalidas"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    usuario_existente = cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()

    if usuario_existente:
        conn.close()
        return jsonify({"mensaje": "El usuario ya existe"}), 409

    bytes_password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(bytes_password, salt)

    try:
        cursor.execute('INSERT INTO usuarios (email, password) VALUES (?, ?)', 
                       (email, hashed_password))
        conn.commit()
        conn.close()

        return jsonify({"mensaje": "Usuario Registrado"}), 201

    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)