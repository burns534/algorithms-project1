def get_user_type():
    print('Please select your user type:')
    print(' 1. A public user')
    print(' 2. The owner of the keys')
    print(' 3. Exit program')
    result = input('Enter your choice: ')
    return result

def public_user_action():
    print('As a public user, what would you like to do?')
    print(' 1. Send an encrypted message')
    print(' 2. Authenticate a digital signature')
    print(' 3. Exit ')
    result = input('Enter your choice: ')
    return result

def owner_user_action():
    print('As the owner of the keys, what would you like to do?')
    print(' 1. Decrypt a received message')
    print(' 2. Digitally sign a message')
    print(' 3. Exit ')
    result = input('Enter your choice: ')
    return result

def public_user_action_handler(action):
    print('public user....', action)
    return

def owner_user_action_handler(action):
    print(action)
    print('owner user....', action)
    return

def program():
    user_type = get_user_type()

    try:
        user_type = int(user_type)
    except ValueError:
        program()
    
    # public user
    if user_type == 1: 
        action = public_user_action()
        public_user_action_handler(action)
    # owner user
    elif user_type == 2:
        action = owner_user_action()
        owner_user_action_handler(action)
    elif user_type == 3:
        print('exiting....')
        return

program()
