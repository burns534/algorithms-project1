import utils

message_queue = []
signature_queue = []

# this probably all needs to be encapsulated in a class. I'm planning on doing that soon
def encrypt(message: str, pub) -> str:
    (e, n) = pub
    cipher_values = []        
    for m in message.encode('ascii'):
        cipher_value = pow(m, e) % n
        cipher_values.append(cipher_value)
    return cipher_values

#Hello from Nathan
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
    message_queue.append(encrypt(message, PUBLIC_KEY))
    print("Message encrypted and sent.")
    print("".join(map(str, message_queue[len(message_queue) - 1])))

def get_available_messages():
    print('Messages available messages:')
    for i, m in enumerate(message_queue):
        cipher_string = "".join(map(str, m))
        print("{}. {}".format(i + 1, cipher_string))
    return ["{}. (length = {})".format(i, len(m)) for i, m in enumerate(message_queue)]

def get_message(index: int) -> str:
    if int(index) - 1 < len(message_queue):
        print(decrypt(message_queue[int(index) - 1], PRIVATE_KEY))
    return None

