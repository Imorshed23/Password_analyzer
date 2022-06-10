import re
import string
import secrets
import hashlib

# This function will check if the password is strong enough
# Paramter: none
# Return value: none
def password_strength_check():
    user_password = input("Enter password: ")
    flag = 0
    while True:
        if (len(user_password) < 8):
            flag = -1
            break
        elif not re.search("[a-z]", user_password):
            flag = -1
            break
        elif not re.search("[A-Z]", user_password):
            flag = -1
            break
        elif not re.search("[0-9]", user_password):
            flag = -1
            break
        elif not re.search("[_@$]", user_password):
            flag = -1
            break
        elif re.search("\s", user_password):
            flag = -1
            break
        else:
            flag = 0
            print("Valid Password")
            break

    if flag == -1:
        print("Not a Valid Password")
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
        return "This is the encryption of your password using SHA-256 method -> " + hash_password

def options():
    try:
        length = int(input("How many characters should your password have: "))
    except ValueError:
        length = int(input("How many characters should your password have: "))
    print(newpassword(length))
    return options()

def main():
    print("Welcome to password analyzer by ilia!")
    password_strength_check()
    options()
if __name__ == '__main__':
    main()




