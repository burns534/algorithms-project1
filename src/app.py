
from backend import Backend
import sys

backend = Backend()

def get_user_type():
    print('Please select your user type:')
    print('\t1. A public user')
    print('\t2. The owner of the keys')
    print('\t3. Exit program')
    return input('Enter your choice: ')

def public_user_action():
    print('As a public user, what would you like to do?')
    print('\t1. Send an encrypted message')
    print('\t2. Authenticate a digital signature')
    print('\t3. Exit')
    return input('Enter your choice: ')

def owner_user_action():
    print('As the owner of the keys, what would you like to do?')
    print('\t1. Decrypt a received message')
    print('\t2. Digitally sign a message')
    print('\t3. Exit')
    return input('Enter your choice: ')

def public_user():
    while True:
        action = public_user_action()
        if action == '3':
            return
        elif action == '2':
            messages = backend.get_encrypted_messages()
            if len(messages) == 0:
                print("There are no signatures to authenticate.")
                continue
            print("The following messages are available: ", end='\n\t')
            print('\n\t'.join(["{}. (length = {})".format(i + 1, len(m)) for i, m in enumerate(messages)]))
            while True:
                try:
                    selection = int(input("Enter your choice: "))
                    is_valid = backend.validate_signature(selection)
                    if is_valid == None:
                        print("error: invalid selection")
                        continue
                    elif is_valid == True:
                        print("Signature is valid.")
                        break
                    else:
                        print("Signature is invalid.")
                        break
                except ValueError:
                    print("error: invalid input")
                    continue
                
        elif action == '1':
            backend.send_message(input("Enter a message: "))
        else:
            print("error: invalid selection")


def owner_user():
    while True:
        action = owner_user_action()
        if action == '3':
            return
        elif action == '2':
            backend.send_signed_message(input("Enter a message: "))
        elif action == '1':
            messages = backend.get_encrypted_messages()
            if len(messages) == 0:
                print("There are no messages to decrypt.")
                continue
            print("The following messages are available: ", end='\n\t')
            print('\n\t'.join(["{}. (length = {})".format(i + 1, len(m)) for i, m in enumerate(messages)]))
            while True:
                try:
                    selection = int(input("Enter your choice: "))
                    message = backend.get_message(selection)
                    if message == None:
                        print("error: invalid selection")
                        continue
                    else:
                        print("Decrypted message: {}".format(message))
                        break

                except ValueError:
                    print("error: invalid input")
                    continue
        else:
            print("error: invalid selection")

def program():
    while True:
        user_type = get_user_type()
        
        # public user
        if user_type == '1':
            public_user()
        # owner user
        elif user_type == '2':
            owner_user()

        elif user_type == '3':
            print('Bye for now!')
            sys.exit(0)

if __name__ == "__main__":
    program()
