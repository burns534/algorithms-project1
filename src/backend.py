from email import charset, message
import utils
import datetime;

message_queue = []
decrypted_messages = []
signature_queue = []
owner_signature = utils.generated_signature()
key = 5

# this probably all needs to be encapsulated in a class. I'm planning on doing that soon
def encrypt(message: str, pub) -> str:
    (e, n) = pub
    cipher_values = []        
    for m in message.encode('ascii'):
        cipher_value = pow(m, e) % n
        cipher_values.append(cipher_value)
    return cipher_values

def decrypt(message: str, priv) -> str:
    plain_values = []
    (d, n) = priv
    for m in message:
        m = int(m)
        c = pow(m, d) % n
        plain_values.append(chr(c))
    return "".join(plain_values)

def generate_rsa_pair():
    (p, q) = (utils.random_prime(1000), utils.random_prime(1000)) # 1000???
    n = p * q
    phi_of_n = (p-1) * (q-1)
    e = utils.get_encryption_key(n, phi_of_n)
    d = utils.get_decryption_key(e, phi_of_n)
    return ((e, n), (d, n))

utils.generate_prime_list(1000) # must be called before random_prime is called
(PUBLIC_KEY, PRIVATE_KEY) = generate_rsa_pair()

def send_message(message: str):
    hashed_header = get_signature()
    message_queue.append(encrypt(hashed_header + '# ' + message, PUBLIC_KEY))    
    print("Message encrypted and sent.")
    print("".join(map(str, message_queue[len(message_queue) - 1])))

def get_available_messages():
    print('Available messages:')
    for i, m in enumerate(message_queue):
        cipher_string = "".join(map(str, m))
        print("{}. {}".format(i + 1, cipher_string))
    return ["{}. (length = {})".format(i, len(m)) for i, m in enumerate(message_queue)]
    
def get_available_decrypted_messages():
    print('Available messages:')
    for i, m in enumerate(decrypted_messages):
        cipher_string = "".join(map(str, m))
        print("{}. {}".format(i + 1, cipher_string))
    return ["{}. (length = {})".format(i, len(m)) for i, m in enumerate(decrypted_messages)]

def get_message(index: int) -> str:
    if int(index) - 1 < len(message_queue):
        decrypted_message = decrypt(message_queue[int(index) - 1], PRIVATE_KEY)
        decrypted_messages.append(decrypted_message)
        print(decrypted_message)
    return None

    

def get_signature():
    hashed_signature = utils.signature_cypher(owner_signature, key)
    return hashed_signature 

def set_signature(signature: str):
    owner_signature = signature.upper()
    return owner_signature

def validate_signature(index: int):
    message = decrypted_messages[int(index) -1]
    hashed_header = message.split('#')[0]
    if (utils.signature_cypher(hashed_header, -5) == owner_signature):
        print('Message is valid.')
        return True
    else:
        print('Message has been altered!!!!')
        return True


 