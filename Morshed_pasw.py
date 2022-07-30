import re
import string
import secrets
import hashlib
import mysql.connector
from mysql.connector import Error
try:
    connection = mysql.connector.connect(host='localhost',
                                         database='project',
                                         user='root',
                                         password='Morshed257')
    mySql_insert_query = """INSERT INTO password (Passwords) 
                               VALUES 
                               (15) """

    if connection.is_connected():
        db_Info = connection.get_server_info()
        print("Connected to MySQL Server version ", db_Info)
        cursor = connection.cursor()
        cursor.execute("select database();")
        record = cursor.fetchone()
        print("You're connected to database: ", record)

except Error as e:
    print("Error while connecting to MySQL", e)
finally:
    if connection.is_connected():
        cursor.close()
        connection.close()
        print("MySQL connection is closed")
print("Welcome to Password Analyzer 1.0")
USER_PASSWORD = input("Please enter password: ")
def password_strength_check():
    flag = 0
    while True:
        if (len(USER_PASSWORD) < 8):
            flag = -1
            break
        elif not re.search("[a-z]", USER_PASSWORD):
            flag = -1
            break
        elif not re.search("[A-Z]", USER_PASSWORD):
            flag = -1
            break
        elif not re.search("[0-9]", USER_PASSWORD):
            flag = -1
            break
        elif not re.search("[_@$]", USER_PASSWORD):
            flag = -1
            break
        elif re.search("\s", USER_PASSWORD):
            flag = -1
            break
        else:
            flag = 0
            print("Valid Password")
            break
    if flag == -1:
        print("Not a Valid Password")
##def file():
    #with open('libarypassw.txt', 'r') as f:
        #common = f.read().splitlines()
    #if USER_PASSWORD in common:
        #print("Password was in a common list.")
def file():
    if USER_PASSWORD in mySql_insert_query:
        print("found")

#password_strength_check()
# Function: This function will create a random password using ascii tool. It will contain letters, digits and punctuation
# Paramter: the length is the only paramter in order to give the oprion to the user what kind of password they want
# return: None
def newpassword(length):
        charachters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(charachters) for i in range(length))
        print("Random password is:", password)
        length = len(password)
        if length < 8:
            print("In order to follow the best security practice, a new password should be at least 8 charachters. ")
        hash_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return "This is the hash of your password using SHA-256 method -> " + hash_password


def options():
    try:
        length = int(input("How many characters should your password have: "))
    except ValueError:
        length = int(input("How many characters should your password have: "))
    print(newpassword(length))
    return options()

def main():
    password_strength_check()
    file()
    options()
if __name__ == '__main__':
    main()





