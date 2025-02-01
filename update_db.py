import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'joone.db')
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
except sqlite3.OperationalError:
    print("is_admin column already exists.")

conn.commit()
conn.close()

print("Database updated successfully!")