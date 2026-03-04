import sqlite3

def crear_base_de_datos():
    conexion = sqlite3.connect('database.db')
    cursor = conexion.cursor()

    sql = """
    DROP TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
    """

    cursor.execute(sql)
    conexion.commit()
    conexion.close()
    print("Base de datos y tabla 'usuarios' creadas con éxito.")

if __name__ == "__main__":
    crear_base_de_datos()