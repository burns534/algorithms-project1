import utils, random, math
from sympy.ntheory import primerange

            
# this probably all needs to be encapsulated in a class. I'm planning on doing that soon
# def encrypt(message: str, pub) -> str:
#     (e, n) = pub
#     cipher_values = []        
#     for m in message.encode('ascii'):
#         cipher_value = pow(m, e) % n
#         cipher_values.append(cipher_value)
#     return cipher_values

# def decrypt(message: str, priv) -> str:
#     plain_values = []
#     (d, n) = priv
#     for m in message:
#         m = int(m)
#         c = pow(m, d) % n
#         plain_values.append(chr(c))
#     return "".join(plain_values)

# def generate_rsa_pair():
#     (p, q) = (utils.random_prime(1000), utils.random_prime(1000)) # 1000???
#     n = p * q
#     phi_of_n = (p-1) * (q-1)
#     e = utils.get_encryption_key(n, phi_of_n)
#     d = utils.get_decryption_key(e, phi_of_n)
#     return ((e, n), (d, n))

# utils.generate_prime_list(1000) # must be called before random_prime is called
# (PUBLIC_KEY, PRIVATE_KEY) = generate_rsa_pair()

class Backend:
    def __init__(self, prime_range=100_000, block_width=256, fermat_iterations=1):
        # self.prime_list = self.generate_prime_list(prime_range)
        self.block_width = block_width
        self.fermat_iterations = fermat_iterations
        (self.public_key, self.private_key) = self.rsa_keygen()

        self.encrypted_messages = []
        self.decrypted_messages = []
        self.signatures = []
        self.owner_signature = self.generated_signature()
        self.key = 5
        return

    def random_prime(self):
        """Returns random prime from backend prime list"""
        return self.prime_list[random.randint(0, len(self.prime_list) - 1)]

    def generate_public_key(self, phi):
        while True:
            candidate_x = random.randint(3, phi - 1) # select random integer in ring of phi
            if math.gcd(candidate_x, phi) == 1: # if candidate is relatively prime with phi, return it
                return candidate_x

    def generate_private_key(self, pub, phi):
        # private key is multiplicative inverse of e in ring of phi
        return utils.extended_gcd(pub, phi)[0] # return the x of 1 = e*x + phi*y, as it is our private key

    def fermat_test(self, p, k):
        for _ in range(k): # perform primality test k times
            if pow(random.randint(1, p), p - 1, p) != 1:
                return False
        return True

    def generate_pseudoprime(self, bits, k):
        while True:
            candidate = random.getrandbits(bits)
            if self.fermat_test(candidate, k):
                return candidate
            
    def rsa_keygen(self):
        p = self.generate_pseudoprime(self.block_width, self.fermat_iterations)
        q = self.generate_pseudoprime(self.block_width, self.fermat_iterations)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = self.generate_public_key(phi)
        return (e, n), (self.generate_private_key(e, phi), n)
    
    def encrypt_message(self, msg):
        print(len(msg))
        result = ""
        e = self.public_key[0]
        n = self.public_key[1]
        print("n: {}".format(n))
        print("n bitlength: {}".format(n.bit_length()))
        threshold = self.block_width // 4 # this converts to bytes and then multiplies by 2 because n is approximately twice bitlength of p or q
        block_bytes = []
        for byte in msg.upper().encode('ascii'):
            block_bytes.append(byte)
            if len(block_bytes) == threshold:
                # byte order doesn't really matter as long as it's the same when we decrypt, but big is the order of the block_bytes list
                # here we accumulate bytes until we have a block, then convert that block to an integer of equal bit length to the public key
                # and then 
                # first convert to integer from bytes
                # then encrypt integer with public key
                # then convert encrypted integer to bytes (threshold bytes long. big enough to hold this because threshold has 2 * block_width bits and n = p * q, each of which are block_width in bit length)
                # then decode to raw_unicode_escape string. This must be done because ascii only supports positive signed bytes and the bytes from the
                # encrypted number can be anything 0-255. Regular unicode also doesn't work because of invalid byte sequences when encoding in the decrypt method
                
                # integer = int.from_bytes(block_bytes, byteorder='big')
                # print("integer from bytes: {}".format(integer))
                # print("integer length: {}".format(integer.bit_length()))
                # cipher_integer = pow(integer, e, n)
                # print("cipher integer: {}".format(cipher_integer))
                # print("cipher integer length: {}".format(cipher_integer.bit_length()))
                
                result += pow(int.from_bytes(block_bytes, byteorder='big'), e, n).to_bytes(threshold, byteorder='big').decode("raw_unicode_escape") 

                # clear the block and start over
                block_bytes.clear()
        if len(block_bytes) > 0:
            # must pad the bytes so we can decrypt properly
            # pad at the front of the bytearray since we know length here and decryption function won't
            # otherwise, the decryption function would be complicated and have to shift afterwards
            padded_bytes = ([0] * (threshold - len(block_bytes)))
            padded_bytes.extend(block_bytes)

            # print(block_bytes)
            
            # integer = int.from_bytes(padded_bytes, byteorder='big')
            # print("integer from bytes: {}".format(integer))
            # print("integer length: {}".format(integer.bit_length()))
            # cipher_integer = pow(integer, e, n)
            # print("cipher integer: {}".format(cipher_integer))
            
            # print("cipher integer length: {}".format(cipher_integer.bit_length()))
            # cipher_bytes = cipher_integer.to_bytes(threshold, byteorder='big')
            # print("cipher bytes: {}".format(cipher_bytes))

            result += pow(int.from_bytes(padded_bytes, byteorder='big'), e, n).to_bytes(threshold, byteorder='big').decode("raw_unicode_escape") 
        return result

    def decrypt_message(self, msg):
        result = ""
        d = self.private_key[0]
        n = self.private_key[1]
        threshold = self.block_width // 4 # this converts to bytes and then multiplies by 2 because n is approximately twice bitlength of p or q
        block_bytes = []
        for byte in msg.encode("raw_unicode_escape"):
            block_bytes.append(byte)
            if len(block_bytes) == threshold:
                # just undoing the encryption process almost exactly the same
                result += pow(int.from_bytes(block_bytes, byteorder='big'), d, n).to_bytes(threshold, byteorder='big').decode('ascii')
                block_bytes.clear()
        return result

    def signature_cypher(self, signature: str, key: int):
        signature = signature.upper()
        alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = ""
        for letter in signature:
            if letter in alpha:
                letter_index = (alpha.find(letter) + key) % len(alpha) 
                result = result +alpha[letter_index]
            else:
                result = result + letter
        return result

    def generated_signature(self):
        generated_string = ''
        for _ in range(10):
            random_integer = random.randint(97, 97 + 26 - 1)
            flip_bit = random.randint(0, 1)
            random_integer = random_integer - 32 if flip_bit == 1 else random_integer
            generated_string += (chr(random_integer))
        
        return generated_string.upper()
    
    def get_signature(self):
        hashed_signature = self.signature_cypher(self.owner_signature, self.key)
        return hashed_signature 

    def set_signature(self, signature: str):
        owner_signature = signature.upper()
        return owner_signature

    def validate_signature(self, index: int):
        message = self.decrypted_messages[int(index) -1]
        hashed_header = message.split('#')[0]
        if (self.signature_cypher(hashed_header, -5) == self.owner_signature):
            return True
        else:
            return False
    
    def send_message(self, message: str):
        hashed_header = self.get_signature()
        self.encrypted_messages.append(self.encrypt_message(hashed_header + '# ' + message))    
        print("Message encrypted and sent.")
        print("".join(map(str, self.encrypted_messages[len(self.encrypted_messages) - 1])))

    def get_available_messages(self):
        print('Available messages:')
        for i, m in enumerate(self.encrypted_messages):
            cipher_string = "".join(map(str, m))
            print("{}. {}".format(i + 1, cipher_string))
        return '\n'.join(["{}. (length = {})".format(i, len(m)) for i, m in enumerate(self.encrypted_messages)])
        
    def get_available_decrypted_messages(self):
        print('Available messages:')
        for i, m in enumerate(self.decrypted_messages):
            cipher_string = "".join(map(str, m))
            print("{}. {}".format(i + 1, cipher_string))
        return '\n'.join(["{}. (length = {})".format(i, len(m)) for i, m in enumerate(self.decrypted_messages)])

    def get_message(self, index):
        if index - 1 < len(self.encrypted_messages):
            decrypted_message = self.decrypt_message(self.encrypted_messages[index - 1])
            self.decrypted_messages.append(decrypted_message)
            print(decrypted_message)

 
if __name__ == "__main__":
    backend = Backend()
    # ciphertext = backend.encrypt_message("""All along I had been living by the mantra suffer now, enjoy later. I finally realized if I really was supposed to be a doctor I wouldn't be suffering through the process and constantly questioning it. I didn't want to risk selling so much of my life for something I chose based on two minutes of skimming the internet and pressure from teachers and family.""")
    ciphertext = backend.encrypt_message("012345678901234567890123456789012345678912345678901234567890123")
    # print(ciphertext)
    print(backend.decrypt_message(ciphertext))