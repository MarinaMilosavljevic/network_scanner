import sqlite3

conn = sqlite3.connect('db.sqlite3')
cursor = conn.cursor()

# Prikaz svih tabela
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
print("Tabele u bazi:", tables)

# Provera da li postoji tvoja tabela
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scanner_scanresult';")
table = cursor.fetchone()
if table:
    print("Tabela 'scanner_scanresult' postoji.")
    
    # Prikaz prvih 5 redova iz te tabele
    cursor.execute("SELECT * FROM scanner_scanresult LIMIT 5;")
    rows = cursor.fetchall()
    for row in rows:
        print(row)
else:
    print("Tabela 'scanner_scanresult' ne postoji.")

conn.close()
