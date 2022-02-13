
import backend 

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
    print('\t3. Exit ')
    return input('Enter your choice: ')

def owner_user_action():
    print('As the owner of the keys, what would you like to do?')
    print('\t1. Decrypt a received message')
    print('\t2. Digitally sign a message')
    print('\t3. Exit ')
    return input('Enter your choice: ')
    

def public_user_action_handler(action: int) -> int:
    action = int(action)
    if action == 1:
        backend.send_message(input("Enter a message: "))
    elif action == 2:
        signatures = backend.get_signatures()
        if len(signatures) > 0:
            print(backend.authenticate_signature(input("Enter your choice: ")))

    elif action == 3:
        return 3
    else:
        print("Error: invalid input")
        return None

def owner_user_action_handler(action: int) -> int:
    action = int(action)
    if action == 1:
        options = backend.get_available_messages()
        if len(options) > 0:
            # validate user input
            print(backend.get_message(input("Enter your choice: ")))

    elif action == 2:
        signatures = backend.get_signatures()
        if len(signatures) > 0:
            print(backend.authenticate_signature(input("Enter your choice: ")))

    elif action == 3:
        return 3
    else:
        print("Error: invalid input")
        return None




def program():
    while True:
        user_type = get_user_type()

        try:
            user_type = int(user_type)
        except ValueError:
            program()
        
        # public user
        if user_type == 1: 
            action = public_user_action()
            if public_user_action_handler(action) == 3:
                return
        # owner user
        elif user_type == 2:
            action = owner_user_action()
            if owner_user_action_handler(action) == 3:
                return
        elif user_type == 3:
            print('exiting....')
            return

if __name__ == "__main__":
    program()
