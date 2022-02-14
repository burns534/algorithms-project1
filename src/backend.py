import utils

message_queue = []
signature_queue = []


# TODO
def encrypt(message: str, pub: int) -> str:
    (e, n) = pub
    cipher_values = []
    ascii_values = utils.stringToAscii(message)
    for c in ascii_values:
        m = int(c)
        cipher_value = pow(m,e) % n
        cipher_values.append(cipher_value)
    return message
# TODO 
def decrypt(message: str, priv: int) -> str:
    (d, n) = priv
    return message

def generate_rsa_pair():
    (p, q) = utils.eratosthenes()
    n = p * q
    phi_of_n = (p-1) * (q-1)
    e = utils.get_encryption_key(n, phi_of_n)
    d = utils.get_decryption_key(e, phi_of_n)
    return ((e, n), (d, n))

(PUBLIC_KEY, PRIVATE_KEY) = generate_rsa_pair()

def send_message(message: str):
    message_queue.append(encrypt(message, PUBLIC_KEY))
    print("Message encrypted and sent.")

# def get_available_messages() -> list(str):
#     # not sure how we're going to store the length of the encrypted messages
#     return ["{}. (length = {})".format(i, len(m)) for i, m in enumerate(message_queue)]

# TODO probably need better error checking here
def get_message(index: int) -> str:
    # pop message queue (message_queue.pop(0))
    if index < len(message_queue):
        return message_queue[index]
    return None

