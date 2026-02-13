import sqlite3

def crear_base_de_datos():
    # Nos conectamos (o creamos) el archivo database.db
    conexion = sqlite3.connect('database.db')
    cursor = conexion.cursor()

    # SQL estricto según tus instrucciones
    sql = """
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'cliente'
    )
    """

    cursor.execute(sql)
    conexion.commit()
    conexion.close()
    print("Base de datos y tabla 'usuarios' creadas con éxito.")

if __name__ == "__main__":
    crear_base_de_datos()