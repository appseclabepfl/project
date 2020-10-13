import mysql.connector

db = mysql.connector.connect(
	host="10.10.10.2",
	user="webserver",
	password="database",
	database="imovies_users",
	port=3306,
	charset="utf8")

print("connected \n")
c = db.cursor(buffered=True, dictionary=True)
c.execute("""SELECT firstname FROM users""")

for row in c:
	print(row['firstname'])

c.close()
