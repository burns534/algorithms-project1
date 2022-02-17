import random, math, hashlib
from functools import reduce

class Backend:
    def __init__(self, block_bitwidth=256, fermat_iterations=1, padding=32):
        self.block_bitwidth = block_bitwidth
        self.fermat_iterations = fermat_iterations
        self.padding = max(8, padding) # must be at least a byte
        self.public_key, self.private_key, self.n = self.rsa_keygen()
        self.encrypted_messages = [] # list of bytes objects
        return
    
    def extended_gcd(self, a, b):
        ''' The extended_gcd function implements the
        extension of Euclid's GCD algorithm to find integers x and y
        such that ax + by = gcd(a, b) '''
        if b == 0:
            return (1, 0, a)
        (x, y, d) = self.extended_gcd(b, a % b)
        return y, x - a // b * y, d

    def generate_public_key(self, phi):
        while True:
            candidate_x = random.randint(3, phi - 1) # select random integer in ring of phi
            if math.gcd(candidate_x, phi) == 1: # if candidate is relatively prime with phi, return it
                return candidate_x

    def generate_private_key(self, pub, phi):
        # private key is multiplicative inverse of e in ring of phi
        return self.extended_gcd(pub, phi)[0] # return the x of 1 = e*x + phi*y, as it is our private key

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
        while True:
            p = self.generate_pseudoprime(self.block_bitwidth // 2, self.fermat_iterations)
            q = self.generate_pseudoprime(self.block_bitwidth // 2, self.fermat_iterations)
            n = p * q
            # have to generate modulus with sufficient bits that blocks will have fewer bits than it
            if n.bit_length() < self.block_bitwidth - self.padding + 8:
                continue
            phi = (p - 1) * (q - 1)
            e = self.generate_public_key(phi)
            return e, self.generate_private_key(e, phi), n

    def encrypt_message(self, msg=None, msg_bytes=None, e=None):
        # allows for encryption with private key as well
        source = None
        if e == None:
            e = self.public_key
        # so we can encrypt bytes or string
        if msg == None and msg_bytes == None:
            return ""
        if msg_bytes != None:
            source = msg_bytes
        else:
            source = msg.encode('raw_unicode_escape')

        threshold = (self.block_bitwidth - self.padding) // 8 
        padded_width = self.block_bitwidth // 8
        block_bytes = []
        result = bytes()
        for byte in source:
            block_bytes.append(byte)
            if len(block_bytes) == threshold:
                result += pow(int.from_bytes(block_bytes, byteorder='big'), e, self.n).to_bytes(padded_width, byteorder='big')
                block_bytes.clear()
        if len(block_bytes) > 0:
            result += pow(int.from_bytes(block_bytes, byteorder='big'), e, self.n).to_bytes(padded_width, byteorder='big')
        
        return result

    def decrypt_message(self, msg_bytes=None, msg=None, d=None):
        if d == None:
            d = self.private_key
        threshold = (self.block_bitwidth - self.padding) // 8  # this converts to bytes
        padded_width = self.block_bitwidth // 8 # this is the number of bytes the encrypted text blocks are padded by
        
        # so we can decrypt bytes or string
        if msg == None and msg_bytes == None:
            return ""
        if msg_bytes != None:
            source = msg_bytes
        else:
            source = msg.encode('raw_unicode_escape')

        
        result = ""
        block_bytes = []
        # number of bytes is now evenly divisible by padded_width since it was used to generate the output from encryption stage
        # therefore, no block_bytes will be empty at the end of the for loop unlike in the encryption stage
        for byte in source:
            block_bytes.append(byte)
            if len(block_bytes) == padded_width:
                # essentially just encryption backwards
                result += pow(int.from_bytes(block_bytes, byteorder='big'), d, self.n).to_bytes(threshold, byteorder='big').decode('raw_unicode_escape')
                block_bytes.clear()
        return result

    def validate_signature(self, index):
        print("validate signature")
        index -= 1
        if index < len(self.encrypted_messages) and index >= 0:
            # first decrypt the encrypted outer message with private key
            inner_message = self.decrypt_message(self.encrypted_messages.pop(index))

            # now gather the hash from the end of the message. md5 digest is 32 chars long
            digest = inner_message[-16:]
            print("digest: {}".format(digest))
            print("test: {}".format(digest.encode('ascii')))
            # now decrypt the encapsulated message with the public key
            plaintext = self.decrypt_message(msg=inner_message[:-16], d=self.public_key)
            # now calculate digest of inner message to compare to digest from outer message
            print("calculated digest: {}".format(hashlib.md5(plaintext.encode('ascii')).digest().decode('raw_unicode_escape')))
            if digest == hashlib.md5(plaintext.encode('ascii')).digest().decode('raw_unicode_escape'):
                return True
            return False
        return None
    
    def encrypt_signed_message(self, message):
        # get hashed message as bytes
        digest = hashlib.md5(message.encode('ascii')).digest()
        print("digest: {}".format(digest))
        inner_message = self.encrypt_message(msg=message, e=self.private_key)
        outer_message = self.encrypt_message(msg_bytes=inner_message + digest)
        decrypted_outer = self.decrypt_message(msg_bytes=outer_message)

        return self.encrypt_message(msg_bytes=self.encrypt_message(msg=message, e=self.private_key) + digest)
        # print("Hash string: {}".format(digest))
        # inner_message = self.encrypt_message(msg_bytes=message.encode('ascii') + digest, e=self.private_key)
        # print("inner message: {}".format(inner_message))
        # print("decrypted inner message: {}".format(self.decrypt_message(msg_bytes=inner_message, d=self.public_key)))
        # outer_message = self.encrypt_message(msg_bytes=inner_message + digest)
        # print("outer message: {}".format(outer_message))
        # print("decrypted outer message: {}".format(self.decrypt_message(msg_bytes=outer_message)))
        # print("fully decrypted: {}".format(self.decrypt_message(msg=self.decrypt_message(msg_bytes=outer_message), d=self.public_key)))
        # return self.encrypt_message(self.encrypt_message(message + diges, self.private_key) + hash_string)
        # return self.encrypt_message(message + hash_string)

    def send_message(self, message):
        self.encrypted_messages.append(self.encrypt_message(message))
    
    def send_signed_message(self, message):
        self.encrypted_messages.append(self.encrypt_signed_message(message))

    def get_encrypted_messages(self):
        return self.encrypted_messages
    
    # def get_signed_message(self, index):
    #     index -= 1
    #     if index < len(self.encrypted_messages) and index >= 0:
    #         return self.decrypt_signed_message(self.encrypted_messages.pop(index))
    #     return None

    def get_message(self, index):
        index -= 1 # user choices indexed starting at 1
        if index < len(self.encrypted_messages) and index >= 0:
            return self.decrypt_message(self.encrypted_messages.pop(index))
        return None
    
    # def get_available_messages(self):
    #     for i, m in enumerate(self.encrypted_messages):
    #         cipher_string = "".join(map(str, m))
    #         print("{}. {}".format(i + 1, cipher_string))
    #     return '\n'.join(["{}. (length = {})".format(i, len(m)) for i, m in enumerate(self.encrypted_messages)])
        
    # def get_available_decrypted_messages(self):
    #     print('Available messages:')
    #     for i, m in enumerate(self.decrypted_messages):
    #         cipher_string = "".join(map(str, m))
    #         print("{}. {}".format(i + 1, cipher_string))
    #     return '\n'.join(["{}. (length = {})".format(i, len(m)) for i, m in enumerate(self.decrypted_messages)])


 
if __name__ == "__main__":
    backend = Backend(block_bitwidth=64, padding=8)
    
    # ciphertext = backend.encrypt_message("""All along I had been living by the mantra suffer now, enjoy later. I finally realized if I really was supposed to be a doctor I wouldn't be suffering through the process and constantly questioning it. I didn't want to risk selling so much of my life for something I chose based on two minutes of skimming the internet and pressure from teachers and family.""")
    # ciphertext = backend.encrypt_message("this is a test")
    # print(ciphertext)
    # print(backend.decrypt_message(ciphertext))

    # ciphertext = backend.encrypt_message(msg_bytes=b'0123456789')
    # print(ciphertext)
    # print(backend.decrypt_message(ciphertext))

    # hash_string = hashlib.md5("hellooooo".encode('raw_unicode_escape')).hexdigest()
    # print(hash_string)
    # print(len(hash_string))

    backend.send_signed_message("mySignature")
    # backend.send_signed_message("another signed message")
    # print(backend.get_encrypted_messages())
    print(backend.validate_signature(1))
