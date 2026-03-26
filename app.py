from functools import wraps
from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import jwt
import datetime
import re
import logging # <-- Nueva importación para los logs

app = Flask(__name__)

# Clave secreta para JWT
app.config['SECRET_KEY'] = 'mi_clave_secreta_universitaria_123'

# ==========================================
# CONFIGURACIÓN DE LOGS PARA EL PROYECTO
# ==========================================
# Se configura para guardar en un archivo local y capturar desde INFO en adelante.
logging.basicConfig(
    filename='registro_eventos.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row 
    return conn

# FUNCIÓN AUXILIAR PARA VALIDAR HTML
def contiene_html(texto):
    if texto is None:
        return False
    patron = re.compile(r'<.*?>')
    return bool(patron.search(texto))

# ==========================================
# ENDPOINTS DE USUARIO
# ==========================================

@app.route('/registro', methods=['POST'])
def registro():
    datos = request.get_json()
    email = datos.get('email')
    password = datos.get('password')
    role = datos.get('role', 'cliente')

    # LOG: Intento de registro (Omitiendo el password por seguridad)
    logging.info(f"Intento de registro para email: {email}")

    if not email or not password:
        # LOG: Datos incompletos
        logging.error("Registro fallido: email o password faltante")
        return jsonify({"error": "Faltan datos"}), 400

    largo_pass = len(password)
    if not (largo_pass > 8 and largo_pass < 10):
        # LOG: Credenciales inválidas por longitud
        logging.warning(f"Registro fallido: Password de {email} no cumple con el rango (9-11 caracteres)")
        return jsonify({"mensaje": "Credenciales Invalidas"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    usuario_existente = cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()

    if usuario_existente:
        conn.close()
        # LOG: Usuario ya existe
        logging.warning(f"Registro fallido: usuario ya existe {email}")
        return jsonify({"mensaje": "El usuario ya existe"}), 409

    bytes_password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(bytes_password, salt)

    try:
        cursor.execute('INSERT INTO usuarios (email, password, role) VALUES (?, ?, ?)', 
                       (email, hashed_password, role))
        conn.commit()
        
        # LOG: Registro exitoso
        logging.info(f"Usuario registrado correctamente: {email}")
        return jsonify({"mensaje": "Usuario Registrado"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


@app.route('/login', methods=['POST'])
def login():
    datos = request.get_json()
    email = datos.get('email')
    password = datos.get('password')

    # LOG: Intento de login
    logging.info(f"Intento de login para usuario {email}")

    if not email or not password:
        return jsonify({"error": "Faltan datos"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    usuario = cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()
    conn.close()

    if not usuario:
        # LOG: Usuario no encontrado
        logging.error(f"Login fallido: El correo {email} no existe en la base de datos")
        return jsonify({"mensaje": "Usuario no encontrado"}), 404

    password_planas = password.encode('utf-8')
    password_hasheada = usuario['password']

    if bcrypt.checkpw(password_planas, password_hasheada):
        # Generar JWT
        payload = {
            'id': usuario['id'],
            'email': usuario['email'],
            'role': usuario['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        # LOG: Login exitoso (Omitiendo JWT y password)
        logging.info(f"Login exitoso usuario {email}. Token JWT emitido.")
        return jsonify({
            "mensaje": "Login exitoso",
            "token": token
        }), 200
    else:
        # LOG: Credenciales incorrectas
        logging.warning(f"Login fallido: Contraseña incorrecta para {email}")
        return jsonify({"mensaje": "Credenciales Invalidas"}), 401


@app.route('/actualizar', methods=['PUT'])
def actualizar():
    datos = request.get_json()
    email = datos.get('email')
    nueva_password = datos.get('password')
    nuevo_role = datos.get('role')

    # LOG: Solicitud de modificación
    logging.info(f"Solicitud de cambio de datos (rol/pass) para {email}")

    if not email:
        return jsonify({"error": "Faltan datos (se requiere email)"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    usuario_existente = cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()

    if not usuario_existente:
        conn.close()
        # LOG: Usuario no encontrado
        logging.error(f"Fallo en actualización: Usuario {email} no existe")
        return jsonify({"mensaje": "El usuario no existe"}), 404

    try:
        if nueva_password:
            largo_pass = len(nueva_password)
            if not (largo_pass > 8 and largo_pass < 10):
                return jsonify({"mensaje": "Credenciales Invalidas"}), 400
            bytes_password = nueva_password.encode('utf-8')
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(bytes_password, salt)
            cursor.execute('UPDATE usuarios SET password = ? WHERE email = ?', (hashed_password, email))
        
        if nuevo_role:
            # LOG: Cambio de privilegios (CRITICAL)
            logging.critical(f"ALERTA: Se ha modificado el ROL del usuario {email}")
            cursor.execute('UPDATE usuarios SET role = ? WHERE email = ?', (nuevo_role, email))

        conn.commit()
        
        # LOG: Actualización exitosa
        logging.info(f"Datos actualizados correctamente para el usuario {email}")
        return jsonify({"mensaje": "Usuario Actualizado"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


# ==========================================
# DECORADOR JWT
# ==========================================

def token_requerido(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({"error": "Formato inválido. Usa 'Bearer <token>'"}), 401

        if not token:
            return jsonify({"error": "Falta el token de autenticación"}), 401

        try:
            usuario_actual = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "El token ha expirado. Inicia sesión de nuevo."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido."}), 401

        return f(usuario_actual, *args, **kwargs)
    return decorador


# ==========================================
# ENDPOINT CENTRAL (Proyecto)
# ==========================================

@app.route('/publicar_articulo', methods=['POST'])
@token_requerido
def publicar_articulo(usuario_actual): 
    datos = request.get_json()
    nombre = datos.get('nombre')
    email_admin = usuario_actual.get('email', 'Desconocido')
    
    # LOG: Intento de publicación
    logging.info(f"Admin {email_admin} intenta registrar artículo: {nombre}")
    
    # VALIDACIÓN DE ROL (Solo Admins)
    if usuario_actual.get('role') != 'admin':
        # LOG: Acceso denegado
        logging.critical(f"ACCESO DENEGADO: Usuario {email_admin} intentó publicar sin permisos")
        return jsonify({
            "error": "Acceso denegado. Se requieren permisos de administrador para añadir inventario."
        }), 403

    descripcion = datos.get('descripcion')
    precio = datos.get('precio')
    cantidad = datos.get('cantidad')
    
    # 1. Validación estricta de Inputs
    if not all([nombre, descripcion, precio is not None, cantidad is not None]):
        return jsonify({"error": "Faltan datos requeridos"}), 400

    if contiene_html(nombre) or contiene_html(descripcion):
        # LOG: Inyección de HTML
        logging.error("SEGURIDAD: Intento de envío de etiquetas HTML en campo nombre/descripción")
        return jsonify({"error": "Entrada inválida: No se permiten etiquetas HTML."}), 400

    try:
        cantidad = int(cantidad)
        precio = float(precio)
        if cantidad < 0 or precio <= 0:
            # LOG: Error de validación numérica
            logging.warning("Datos inválidos: Precio o cantidad no son números positivos")
            return jsonify({"error": "La cantidad o precio no son válidos"}), 400
    except ValueError:
        logging.warning("Datos inválidos: Precio o cantidad no son números positivos")
        return jsonify({"error": "El precio o la cantidad deben ser valores numéricos"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
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
        ''', (nombre, descripcion, precio, cantidad))
        
        conn.commit()
        
        # LOG: Artículo creado con éxito
        logging.info(f"Nuevo artículo registrado: {nombre} con éxito")
        return jsonify({"mensaje": "Artículo publicado exitosamente"}), 201

    except Exception as e:
        return jsonify({"error": f"Error interno en la BD: {str(e)}"}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, port=5000)