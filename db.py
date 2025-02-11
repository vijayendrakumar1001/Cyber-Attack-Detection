import sqlite3
import pandas as pd

df = pd.read_csv("ips.csv")  

conn = sqlite3.connect("blocklistedip.db")
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip_address TEXT PRIMARY KEY
    )
""")

df.to_sql("blocked_ips", conn, if_exists="replace", index=False)

conn.commit()
conn.close()
print("CSV data loaded into database successfully!")
