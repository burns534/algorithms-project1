import random
import math
from turtle import back
from sympy.ntheory import primerange

def extended_gcd(a=1, b=1):
    ''' The extended_gcd function implements the
    extension of Euclid's GCD algorithm to find integers x and y
    such that ax + by = gcd(a, b) '''
    if b == 0:
        return (1, 0, a)
    (x, y, d) = extended_gcd(b, a % b)
    return y, x - a // b * y, d

class Backend:
    def __init__(self, prime_range=100_000, block_width=256, fermat_iterations=1):
        # self.prime_list = self.generate_prime_list(prime_range)
        self.prime_list = list(primerange(10000))
        self.block_width = block_width
        self.fermat_iterations = fermat_iterations
        (self.public_key, self.private_key) = self.rsa_keygen()
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
        return extended_gcd(pub, phi)[0] # return the x of 1 = e*x + phi*y, as it is our private key

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

    # def encrypt_message(self, msg):
    #     result = ""
    #     e = self.public_key[0]
    #     n = self.public_key[1]
    #     for byte in msg.upper().encode('ascii'):
    #         result += chr(pow(byte, e, n))
    #     return result
    
    def encrypt_message(self, msg):
        result = ""
        e = self.public_key[0]
        n = self.public_key[1]
        print("n: {}".format(n))
        threshold = self.block_width // 4 # this converts to bytes and then multiplies by 2 because n is approximately twice bitlength of p or q
        block_bytes = []
        for byte in msg.upper().encode('ascii'):
            block_bytes.append(byte)
            if len(block_bytes) == threshold:
                # byte order doesn't really matter as long as it's the same when we decrypt, but big is the order of the block_bytes list
                # here we accumulate bytes until we have a block, then convert that block to an integer of equal bit length to the public key
                # and then 

                # unimplemented
                block_bytes.clear()
        if len(block_bytes) > 0:
            # must pad the bytes so we can decrypt properly
            # block_bytes.extend([0] * (threshold - len(block_bytes)))
            # pad at the front of the bytearray since we know length and decryption function won't
            tmp = ([0] * (threshold - len(block_bytes)))
            tmp.extend(block_bytes)
            block_bytes = tmp

            print(block_bytes)
            integer = int.from_bytes(block_bytes, byteorder='big')
            print("integer from bytes: {}".format(integer))
            cipher_integer = pow(integer, e, n)
            print("cipher integer: {}".format(cipher_integer))
            cipher_bytes = cipher_integer.to_bytes(threshold, byteorder='big')
            print("cipher bytes: {}".format(cipher_bytes))

            return pow(int.from_bytes(block_bytes, byteorder='big'), e, n).to_bytes(threshold, byteorder='big').decode("raw_unicode_escape") 

        return result

    def decrypt_message(self, msg):
        result = ""
        d = self.private_key[0]
        n = self.private_key[1]
        threshold = self.block_width // 4 # this converts to bytes and then multiplies by 2 because n is approximately twice bitlength of p or q
        block_bytes = []
        for byte in ciphertext.encode("raw_unicode_escape"):
            block_bytes.append(byte)
            if len(block_bytes) == threshold:
                new_cipher_integer = int.from_bytes(block_bytes, byteorder='big')
                new_integer = pow(new_cipher_integer, d, n)
                block_bytes = new_integer.to_bytes(threshold, byteorder='big')
                return block_bytes.decode('ascii')

            

def signature_cypher(signature: str, key: int):
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

def generated_signature():
    generated_string = ''
    for _ in range(10):
        random_integer = random.randint(97, 97 + 26 - 1)
        flip_bit = random.randint(0, 1)
        random_integer = random_integer - 32 if flip_bit == 1 else random_integer
        generated_string += (chr(random_integer))
    
    return generated_string.upper()


if __name__ == "__main__":
    backend = Backend()
    ciphertext = backend.encrypt_message("test message")
    print(ciphertext)
    print(backend.decrypt_message(ciphertext))