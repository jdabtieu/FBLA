from cs50 import SQL
import os
import shutil

open("database.db", "w").close()

db = SQL("sqlite:///database.db")

email = input("Email for admin account: ")

# Create database
db.execute("CREATE TABLE 'users' ('id' integer PRIMARY KEY NOT NULL, 'username' varchar(20) NOT NULL, 'password' varchar(64) NOT NULL, 'email' varchar(128), 'join_date' datetime NOT NULL DEFAULT (0), 'admin' boolean NOT NULL DEFAULT (0), 'banned' boolean NOT NULL DEFAULT (0), 'verified' boolean NOT NULL DEFAULT (0), 'twofa' boolean NOT NULL DEFAULT (0))")
db.execute("CREATE TABLE 'problems' ('id' integer PRIMARY KEY NOT NULL, 'type' text NOT NULL, 'description' text NOT NULL, 'a' text NOT NULL, 'b' text, 'c' text, 'd', 'correct' text NOT NULL, 'category' text NOT NULL, 'difficulty' text NOT NULL, 'draft' boolean NOT NULL DEFAULT(0), 'deleted' boolean NOT NULL DEFAULT(0))")
db.execute("CREATE TABLE 'submissions' ('id' integer PRIMARY KEY, 'user_id' integer, 'score' integer NOT NULL DEFAULT(0), 'date' datetime NOT NULL)")
db.execute("CREATE TABLE 'submissions_data' ('sub_id' integer NOT NULL, 'problem_id' integer NOT NULL, 'answer' text NOT NULL, 'correct' boolean NOT NULL DEFAULT(0))")
db.execute("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$ENIhrB05$b3e9121aba89148cdbcd66774df3fb25a93bb471f194fb910e5a6929f5651df9', ?, datetime('now'), 1, 0, 1, 0)", email)
db.execute("INSERT INTO 'submissions' VALUES(0, 0, 0, datetime('now'))")

# Configure application
os.mkdir("logs")
import daily_tasks
shutil.copy2("default_settings.py", "settings.py")