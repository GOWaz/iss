import sqlite3

conn = sqlite3.connect('userDB.db')
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_login BOOLEAN DEFAULT TRUE,
    type VARCHAR(100),
    UNIQUE(username)  -- Ensure usernames are unique
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS userDetails (
    user_id INTEGER PRIMARY KEY,
    phone_number VARCHAR(20),
    residence VARCHAR(255),
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")

cur.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        user_id INTEGER PRIMARY KEY,
        public_key TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
''')

cur.execute('''
    CREATE TABLE IF NOT EXISTS cerKey (
        user_id INTEGER PRIMARY KEY,
        public_key TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
''')

conn.commit()
conn.close()
