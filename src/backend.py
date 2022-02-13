import utils

message_queue = []
signature_queue = []


# TODO
def encrypt(message: str, pub: int) -> str:
    return message
# TODO
def decrypt(message: str, priv: int) -> str:
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


def authenticate_signature(index: int) -> str:
    # pop signature queue
    return "There are no signatures to authenticate."

# def get_signatures() -> list(str):
#     ["{}. {}".format(i, m) for i, m in enumerate(signature_queue)]