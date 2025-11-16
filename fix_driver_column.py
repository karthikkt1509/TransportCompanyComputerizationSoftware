import sqlite3

conn = sqlite3.connect("tccs.db")
cur = conn.cursor()

cur.execute("ALTER TABLE truck_assignment ADD COLUMN driver_id TEXT;")
conn.commit()

print("driver_id column added")
conn.close()
