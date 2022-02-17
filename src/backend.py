import random, math, hashlib

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
            # here we divide block_bitwidth by 2 so that when the numbers are multiplied we end up with
            # n being approximately block_bitwidth bits in length
            p = self.generate_pseudoprime(self.block_bitwidth // 2, self.fermat_iterations)
            q = self.generate_pseudoprime(self.block_bitwidth // 2, self.fermat_iterations)
            n = p * q
            # have to generate modulus with sufficient bits that blocks will have fewer bits than it
            if n.bit_length() < self.block_bitwidth - self.padding + 8:
                continue
            phi = (p - 1) * (q - 1)
            e = self.generate_public_key(phi)
            return e, self.generate_private_key(e, phi), n

    def encrypt_bytes(self, msg_bytes=None, e=None):
        # allows for encryption with private key as well
        if e == None:
            e = self.public_key

        threshold = (self.block_bitwidth - self.padding) // 8 
        padded_width = self.block_bitwidth // 8
        block_bytes = []
        result = bytes()
        for byte in msg_bytes:
            block_bytes.append(byte)
            if len(block_bytes) == threshold:
                result += pow(int.from_bytes(block_bytes, byteorder='big'), e, self.n).to_bytes(padded_width, byteorder='big')
                block_bytes.clear()
        if len(block_bytes) > 0:
            result += pow(int.from_bytes(block_bytes, byteorder='big'), e, self.n).to_bytes(padded_width, byteorder='big')
        return result

    def decrypt_bytes(self, msg_bytes=None, d=None):
        if d == None:
            d = self.private_key

        padded_width = self.block_bitwidth // 8 
        result = bytes()
        block_bytes = []
        # number of bytes is now evenly divisible by padded_width since it was used to generate the output from encryption stage
        # therefore, no block_bytes will be empty at the end of the for loop unlike in the encryption stage
        for byte in msg_bytes:
            block_bytes.append(byte)
            if len(block_bytes) == padded_width:
                # convert padded blocks to integer and decrypt
                integer = pow(int.from_bytes(block_bytes, byteorder='big'), d, self.n)
                # now convert the integer to bytes with no zero padding
                # plus 7 guarantees the floor division returns the correct number of bytes to represent the integer
                # otherwise something like 0000 0001 with a bit length of 1 would give 0 when divided by 8
                result += integer.to_bytes((integer.bit_length() + 7) // 8, byteorder='big')
                block_bytes.clear()
        return result

    def validate_signature(self, index):
        index -= 1
        if index < len(self.encrypted_messages) and index >= 0:
            # first decrypt the encrypted outer message with private key
            outer_message = self.decrypt_bytes(self.encrypted_messages.pop(index))
     
            # now gather the hash from the end of the message. md5 digest is 16 bytes long
            digest = outer_message[-16:]
 
            # now decrypt the encapsulated message with the public key
            plaintext = self.decrypt_bytes(outer_message[:-16], self.public_key)
            
            # now calculate digest of inner message to compare to digest from outer message
            if digest == hashlib.md5(plaintext).digest():
                return True, plaintext.decode("raw_unicode_escape")
            return False, None
        return None, None
    
    def encrypt_signed_message(self, message):
        # get hashed message as bytes. MD5 hash is commonly used for RSA signatures
        digest = hashlib.md5(message.encode('ascii')).digest()
  
        """
        1. Encrypt the message with the private key
        2. Then attach the digest to the enrypted bytes of the first step
        3. Then encrypt the joined bytes with the public key
        For example, if we are signing a message from alice to bob,
        the outer message is encrypted with bob's public key, so it is safe to transmit over the network.
        Only ob can decrypt it. Once bob decrypts this message, he knows in advance that the md5 hash has been used
        and can separate it from the body of the message. Once this is done, he can decrypt the body of the inner message
        using alice's public key. He can then calculate the md5 hash of the result, and if it matches the digest sent by alice,
        it proves that the inner message must have been encrypted by alice's private key, thereby authenticating alice.
        """
        return self.encrypt_bytes(self.encrypt_bytes(message.encode('raw_unicode_escape'), self.private_key) + digest)
 
    def send_message(self, message):
        self.encrypted_messages.append(self.encrypt_bytes(message.encode('raw_unicode_escape')))
    
    def send_signed_message(self, message):
        self.encrypted_messages.append(self.encrypt_signed_message(message))

    def get_encrypted_messages(self):
        return self.encrypted_messages
    
    def get_message(self, index):
        index -= 1 # user choices indexed starting at 1
        if index < len(self.encrypted_messages) and index >= 0:
            return self.decrypt_bytes(self.encrypted_messages.pop(index)).decode('raw_unicode_escape')
        return None


