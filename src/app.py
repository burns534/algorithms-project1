
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
    print('\t2. Exit ')
    return input('Enter your choice: ')

def owner_user_action():
    print('As the owner of the keys, what would you like to do?')
    print('\t1. Decrypt a received message')
    print('\t2. Validate Signature')
    print('\t3. Set Signature')
    print('\t4. Exit ')
    return input('Enter your choice: ')
    
    
def public_user_action_handler(action: int) -> int:
    action = int(action)
    if action == 1:
        backend.send_message(input("Enter a message: "))
    elif action == 2:
        return 3
    else:
        print("Error: invalid input")
        return None

def public_user():
    while True:
        action = public_user_action()
        if action == '3':
            return
        elif action == '2':
            print("The following messages are available:")
            print(backend.get_available_messages())
            while True:
                try:
                    selection = int(input("Enter your choice: "))
                    if backend.validate_signature(selection):
                        print("Signature is valid.")
                    else:
                        print("invalid signature")
                    break
                except ValueError:
                    continue
        elif action == '1':
            backend.send_message(backend.encrypt_message(input("Enter a message: ")))


def owner_user_action_handler(action):
    action = int(action) 
    if action == '1':
        options = backend.get_available_messages()
        if len(options) > 0:
            print(backend.get_message(input("Enter your choice: ")))

    elif action == '2':
        options = backend.get_available_decrypted_messages()
        if len(options) > 0:
            while input("Select message to validate"):
                print(backend.validate_signature(input("Select message to validate: ")))
        else:
            print("There are no signatures to authenticate.")
    elif action == '3':
        backend.set_signature(input('Please enter signature: '))
    else:
        print("Error: invalid input")
        return None

def program():
    while True:
        user_type = get_user_type()
        
        # public user
        if user_type == '1':
            public_user()
        # owner user
        elif user_type == '2':
            owner_user_action_handler(input)

        elif user_type == '3':
            print('Bye for now!')
            sys.exit(0)

if __name__ == "__main__":
    program()
