import sqlite3


def db_adduser(command):
  """The function receives a SQL command (string) as a parameter.
  This function is activated after the client has successfully gone through all the data checks
  in the 'Sign Up' page.
  This function adds a new user, according to supplied SQL command."""
  conn = database_connection()
  cursor = conn.cursor()
  cursor.execute(command)
  conn.commit()

def check_user(sql_command):
  """The function receives a SQL command (string) as a parameter.
  This function is activated after the client has successfully gone through some of the data checks
  in the 'Sign Up' page.
  This function checks if a username already exists in the database, according to the given SQL
  command, and returns an appropriate message."""
  conn = database_connection()
  cursor = conn.cursor()
  cursor.execute(sql_command)
  found_data = cursor.fetchone()
  if found_data:  # found_data isn't empty
    return True  # User exists in the db
  else:
    return False  # User does not exist in the db

def database_connection():
  """The function doesn't receive any parameters.
  This function establishes a connection to an SQLite database file named "UsersInfo.db", and
  afterwards returns the connection object."""
  connection = sqlite3.connect("UsersInfo.db")# Use the cursor to execute SQL statements
  return connection


# The code I used for making a new SQLite database
# sql_command = f"""CREATE TABLE IF NOT EXISTS UsersInfo(
#            ID INTEGER PRIMARY KEY,
#            username TEXT,
#            password TEXT);"""
# db_adduser(sql_command)
