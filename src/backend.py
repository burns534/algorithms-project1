import random, math, hashlib, binascii

class Backend:
    def __init__(self, block_bitwidth=256, fermat_iterations=1):
        self.block_bitwidth = block_bitwidth
        self.fermat_iterations = fermat_iterations
        self.public_key, self.private_key, self.n = self.rsa_keygen()
        self.encrypted_messages = []
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
        p = self.generate_pseudoprime(self.block_bitwidth // 2, self.fermat_iterations)
        q = self.generate_pseudoprime(self.block_bitwidth // 2, self.fermat_iterations)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = self.generate_public_key(phi)
        return e, self.generate_private_key(e, phi), n
    
    def encrypt_message(self, msg, e=None):
        print(len(msg))
        result = ""
        if e == None:
            e = self.public_key
        # print("n: {}".format(self.n))
        # print("n bitlength: {}".format(self.n.bit_length()))
        threshold = self.block_bitwidth // 8 # this converts to bytes
        block_bytes = []
        print("encrypting message: {}".format(msg))
        message_bytes = msg.upper().encode('raw_unicode_escape')
        print("message bytes: {}".format(message_bytes))
        result_bytes = []
        for byte in msg.upper().encode('raw_unicode_escape'):
            block_bytes.append(byte)
            if len(block_bytes) == threshold:
                # byte order doesn't really matter as long as it's the same when we decrypt, but big is the order of the block_bytes list
                # here we accumulate bytes until we have a block, then convert that block to an integer of equal bit length to the public key
                # and then 
                # first convert to integer from bytes
                # then encrypt integer with public key
                # then convert encrypted integer to bytes (threshold bytes long. big enough to hold this because threshold has 2 * block_bitwidth bits and n = p * q, each of which are block_bitwidth in bit length)
                # then decode to raw_unicode_escape string. This must be done because ascii only supports positive signed bytes and the bytes from the
                # encrypted number can be anything 0-255. Regular unicode also doesn't work because of invalid byte sequences when encoding in the decrypt method
                print("block_bytes: {}".format(block_bytes))
                integer = int.from_bytes(block_bytes, byteorder='big')
                print("integer from bytes: {}".format(integer))
                print("integer length: {}".format(integer.bit_length()))
                cipher_integer = pow(integer, e, self.n)
                print("cipher integer: {}".format(cipher_integer))
                print("cipher integer length: {}".format(cipher_integer.bit_length()))
                cipher_bytes = cipher_integer.to_bytes(threshold, byteorder='big')
                print("cipher_bytes: {}".format(cipher_bytes))
                # cipher_text = cipher_bytes.decode('raw_unicode_escape')
                # print("cipher_text: {}".format(cipher_text))
                result_bytes.append(cipher_bytes)
                # result += pow(int.from_bytes(block_bytes, byteorder='big'), e, self.n).to_bytes(threshold, byteorder='big').decode("raw_unicode_escape") 

                # clear the block and start over
                block_bytes.clear()
        if len(block_bytes) > 0:
            print("block_bytes: {}".format(block_bytes))
            # must pad the bytes so we can decrypt properly
            # pad at the front of the bytearray since we know length here and decryption function won't
            # otherwise, the decryption function would be complicated and have to shift afterwards
            padded_bytes = ([0] * (threshold - len(block_bytes)))
            padded_bytes.extend(block_bytes)

            print("padded_bytes: {}".format(padded_bytes))
            
            print("block_bytes: {}".format(block_bytes))
            integer = int.from_bytes(block_bytes, byteorder='big')
            print("integer from bytes: {}".format(integer))
            print("integer length: {}".format(integer.bit_length()))
            cipher_integer = pow(integer, e, self.n)
            print("cipher integer: {}".format(cipher_integer))
            print("cipher integer length: {}".format(cipher_integer.bit_length()))
            cipher_bytes = cipher_integer.to_bytes(threshold, byteorder='big')
            print("cipher_bytes: {}".format(cipher_bytes))

            result_bytes.append(cipher_bytes)

            # result += pow(int.from_bytes(padded_bytes, byteorder='big'), e, self.n).to_bytes(threshold, byteorder='big').decode("raw_unicode_escape") 
        
        
        print("full cipher bytes: {}".format(result_bytes))

        d = self.private_key

        new_cipher_bytes = []

        plaintext_result = ""
    
    
        print("message bytes: {}".format(result_bytes))
        for byte in result_bytes:
            # print("new_cipher_bytes: {}".format(new_cipher_bytes))
            # new_cipher_integer = int.from_bytes(new_cipher_bytes, byteorder='big')
            new_cipher_integer = int.from_bytes(byte, byteorder='big')
            print("new_cipher_integer: {}".format(new_cipher_integer))
            new_integer = pow(new_cipher_integer, d, self.n)
            print("new_integer: {}".format(new_integer))
            new_message_bytes = new_integer.to_bytes(threshold, byteorder='big')
            print("new_message_bytes: {}".format(new_message_bytes))
            plaintext = new_message_bytes.decode('raw_unicode_escape')
            print("plaintext: {}".format(plaintext))
            
            plaintext_result += plaintext
        
        return result

    def decrypt_message(self, msg, d=None):
        result = ""
        if d == None:
            d = self.private_key
        threshold = self.block_bitwidth // 4 # this converts to bytes and then multiplies by 2 because n is approximately twice bitlength of p or q
        block_bytes = []
        for byte in msg.encode("raw_unicode_escape"):
            block_bytes.append(byte)
            if len(block_bytes) == threshold:
                # just undoing the encryption process almost exactly the same
                result += pow(int.from_bytes(block_bytes, byteorder='big'), d, self.n).to_bytes(threshold, byteorder='big').decode('raw_unicode_escape')
                block_bytes.clear()
        return result

    # def validate_signature(self, index: int):
    #     message = self.decrypted_messages[int(index) -1]
    #     hashed_header = message.split('#')[0]
    #     if (self.signature_cypher(hashed_header, -5) == self.owner_signature):
    #         return True
    #     else:
    #         return False

    def validate_signature(self, index):
        print("validate signature")
        index -= 1
        if index < len(self.encrypted_messages) and index >= 0:
            # first decrypt the encrypted container message with private key
            message = self.decrypt_message(self.encrypted_messages.pop(index))
            print(message)
            # now gather the hash from the end of the message. md5 digest is 32 chars long
            hash_string = message[-32:]
            print(len(hash_string))
            print("Hash string: {}".format(hash_string))
            # now decrypt the encapsulated message with the public key to authenticate
            inner_message = self.decrypt_message(message, self.public_key)
            print(inner_message)
            return True
        return None
    
    def encrypt_signed_message(self, message):
        hash_string = hashlib.md5(message.encode('raw_unicode_escape')).hexdigest()
        print("Hash string: {}".format(hash_string))
        # return self.encrypt_message(self.encrypt_message(message + hash_string, self.private_key) + hash_string)
        return self.encrypt_message(message + hash_string)

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
    backend = Backend(block_bitwidth=64)
    
    # ciphertext = backend.encrypt_message("""All along I had been living by the mantra suffer now, enjoy later. I finally realized if I really was supposed to be a doctor I wouldn't be suffering through the process and constantly questioning it. I didn't want to risk selling so much of my life for something I chose based on two minutes of skimming the internet and pressure from teachers and family.""")
    # ciphertext = backend.encrypt_message("this is a test")
    # # print(ciphertext)
    # print(backend.decrypt_message(ciphertext))

    backend.encrypt_message("0123456789")

    # hash_string = hashlib.md5("hellooooo".encode('raw_unicode_escape')).hexdigest()
    # print(hash_string)
    # # print(len(hash_string))

    # message = "topSecret"

    # encrypted_message = backend.encrypt_message(message + hash_string)
    # print(backend.decrypt_message(encrypted_message))

    # b = binascii.b2a_hex("hello world".upper().encode('raw_unicode_escape'))
    # print(binascii.a2b_hex(b))
    # backend.encrypt_message("topSecret")

    # backend.send_signed_message("mySignature")
    # backend.validate_signature(1)