import os
from functools import wraps
from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import jwt
import datetime
import re
import logging

app = Flask(__name__)


# 1. CONFIGURACIÓN DE LOGS  

logging.basicConfig(
    filename='registro_eventos.log',
    level=logging.DEBUG,  # Permite capturar los 4 niveles solicitados
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# CORRECCIÓN SEGURIDAD: Evitar clave hardcoded (CWE-259)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_proyecto_universitario_segura_99x')

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row 
    return conn

# FUNCIÓN AUXILIAR PARA VALIDAR/SANEAR HTML (OWASP - Prevención XSS)
def contiene_html(texto):
    if texto is None: return False
    patron = re.compile(r'<.*?>')
    return bool(patron.search(texto))

# 
# 2. DECORADOR JWT (Control de Acceso OWASP)
# 
def token_requerido(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                logging.warning("WARNING: Formato de token inválido enviado.")
                return jsonify({"error": "Formato inválido. Usa 'Bearer <token>'"}), 401

        if not token:
            logging.warning("WARNING: Intento de acceso sin token.")
            return jsonify({"error": "Falta el token de autenticación"}), 401

        try:
            usuario_actual = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            logging.warning("WARNING: Token expirado presentado.")
            return jsonify({"error": "El token ha expirado."}), 401
        except jwt.InvalidTokenError:
            logging.error("ERROR: Token de seguridad inválido detectado.")
            return jsonify({"error": "Token inválido."}), 401

        return f(usuario_actual, *args, **kwargs)
    return decorador

# 3. ENDPOINTS DE USUARIO Y SESIÓN

@app.route('/registro', methods=['POST'])
def registro():
    logging.debug("DEBUG: Iniciando proceso de registro.")
    datos = request.get_json()
    email = datos.get('email')
    password = datos.get('password')

    if not email or not password:
        logging.warning("WARNING: Intento de registro con campos vacíos.")
        return jsonify({"error": "Faltan datos"}), 400

    # OWASP: Hashing de contraseña
    password_hasheada = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # OWASP: Consulta preparada contra Inyección SQL
        cursor.execute('INSERT INTO usuarios (email, password, role) VALUES (?, ?, ?)', 
                       (email, password_hasheada, 'usuario'))
        conn.commit()
        conn.close()
        logging.info(f"INFO: Nuevo usuario registrado: {email}")
        return jsonify({"mensaje": "Usuario registrado"}), 201
    except sqlite3.IntegrityError:
        logging.error(f"ERROR: Email duplicado en registro: {email}")
        return jsonify({"error": "El email ya existe"}), 400

@app.route('/login', methods=['POST'])
def login():
    logging.debug("DEBUG: Procesando solicitud de login.")
    datos = request.get_json()
    email = datos.get('email')
    password = datos.get('password')

    conn = get_db_connection()
    usuario = conn.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()
    conn.close()

    if usuario and bcrypt.checkpw(password.encode('utf-8'), usuario['password']):
        payload = {
            'id': usuario['id'],
            'email': usuario['email'],
            'role': usuario['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        logging.info(f"INFO: Login exitoso para {email}")
        return jsonify({"token": token}), 200
    
    logging.warning(f"WARNING: Intento de login fallido para {email}")
    return jsonify({"mensaje": "Credenciales incorrectas"}), 401

@app.route('/actualizar', methods=['PUT'])
def actualizar():
    logging.debug("DEBUG: Iniciando proceso de actualización de datos.")
    datos = request.get_json()
    email = datos.get('email')
    nueva_password = datos.get('password')
    nuevo_role = datos.get('role')

    logging.info(f"INFO: Solicitud de modificación enviada para {email}")

    if not email:
        logging.warning("WARNING: Actualización fallida por falta de email.")
        return jsonify({"error": "Faltan datos (email requerido)"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    usuario = cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()

    if not usuario:
        conn.close()
        logging.error(f"ERROR: Intento de actualizar usuario inexistente: {email}")
        return jsonify({"mensaje": "El usuario no existe"}), 404

    try:
        if nueva_password:
            largo_pass = len(nueva_password)
            if not (largo_pass > 8 and largo_pass < 10):
                logging.warning(f"WARNING: Password nueva de {email} no cumple requisitos de longitud.")
                return jsonify({"mensaje": "Credenciales Invalidas"}), 400
            
            hashed = bcrypt.hashpw(nueva_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('UPDATE usuarios SET password = ? WHERE email = ?', (hashed, email))
        
        if nuevo_role:
            # OWASP/Seguridad: Registro crítico de cambio de privilegios
            logging.critical(f"CRITICAL: CAMBIO DE PRIVILEGIOS. Usuario {email} ahora es {nuevo_role}")
            cursor.execute('UPDATE usuarios SET role = ? WHERE email = ?', (nuevo_role, email))

        conn.commit()
        logging.info(f"INFO: Datos de {email} actualizados correctamente.")
        return jsonify({"mensaje": "Usuario Actualizado"}), 200
    except Exception as e:
        logging.error(f"ERROR: Fallo técnico en actualización: {str(e)}")
        return jsonify({"error": "Error interno"}), 500
    finally:
        conn.close()

# 4. ENDPOINT DE INVENTARIO (Protegido)

@app.route('/publicar_articulo', methods=['POST'])
@token_requerido
def publicar_articulo(usuario_actual): 
    datos = request.get_json()
    nombre = datos.get('nombre')
    email_admin = usuario_actual.get('email', 'Desconocido')
    
    logging.debug(f"DEBUG: El administrador {email_admin} intenta publicar un artículo.")
    
    # OWASP: Verificación de Rol (Broken Access Control)
    if usuario_actual.get('role') != 'admin':
        logging.critical(f"CRITICAL: ACCESO DENEGADO. {email_admin} intentó publicar sin ser admin.")
        return jsonify({"error": "Acceso denegado. Se requieren permisos de administrador."}), 403

    descripcion = datos.get('descripcion')
    precio = datos.get('precio')
    cantidad = datos.get('cantidad')
    
    # Validación de campos
    if not all([nombre, descripcion, precio is not None, cantidad is not None]):
        logging.warning("WARNING: Publicación fallida. Campos incompletos.")
        return jsonify({"error": "Faltan datos requeridos"}), 400

    # OWASP: Prevención de XSS
    if contiene_html(nombre) or contiene_html(descripcion):
        logging.error(f"ERROR: Intento de XSS detectado en publicación por {email_admin}")
        return jsonify({"error": "Entrada inválida: No se permiten etiquetas HTML."}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS articulos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                descripcion TEXT NOT NULL,
                precio REAL NOT NULL,
                cantidad INTEGER NOT NULL
            )
        ''')
        
        cursor.execute('''
            INSERT INTO articulos (nombre, descripcion, precio, cantidad) 
            VALUES (?, ?, ?, ?)
        ''', (nombre, descripcion, float(precio), int(cantidad)))
        
        conn.commit()
        logging.info(f"INFO: Artículo '{nombre}' registrado con éxito por {email_admin}")
        return jsonify({"mensaje": "Artículo publicado exitosamente"}), 201

    except Exception as e:
        logging.error(f"ERROR: Fallo en BD al registrar artículo: {str(e)}")
        return jsonify({"error": "Error interno en la BD"}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=False, port=5000)