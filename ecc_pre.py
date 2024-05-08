import ecdsa
from ecdsa.curves import SECP256k1
import random
import hashlib
import math
from ecdsa.numbertheory import inverse_mod
from ecdsa import ellipticcurve, numbertheory
from eth_hash.auto import keccak

class EncryptedCommunication:
    def __init__(self):
        self.curve = SECP256k1
        self.Q = int(self.curve.order)
        self.P = self.curve.generator
        
        self.id_a = 1234
        self.a_x = None
        self.a_y = None
        self.a_xP = None
        self.a_yP = None

        self.id_b = 4321
        self.b_x = None
        self.b_y = None
        self.b_xP = None
        self.b_yP = None

        self.c = None
        self.l_bits = None
        self.n_bits = None

    def hash1(self, message, sigma, idA, pkA1, pkA2):
        mega_string = str(message) + str(sigma) + str(idA) + str(pkA1) + str(pkA2)
        #return int(int(hashlib.sha256(mega_string.encode()).hexdigest(), 16) % self.Q)
        hash_bytes = keccak(mega_string.encode())
        return int.from_bytes(hash_bytes, byteorder='big') % self.Q
    
    def hash2(self, n, seed_value):
        hash_value = hash((n, seed_value))
        result = hash_value & ((1 << n) - 1)
        if result < (1 << (n - 1)):
            result += (1 << (n - 1))
        return bin(result)[2:]

    def hash3(self, c1, c2, c3, c4):
        mega_string = str(c1) + str(c2) + str(c3) + str(c4)
        #return int(int(hashlib.sha256(mega_string.encode()).hexdigest(), 16) % self.Q)
        hash_bytes = keccak(mega_string.encode())
        return int.from_bytes(hash_bytes, byteorder='big') % self.Q

    def hash4(self, idA, idB, pkB1x, pkB1y):
        mega_string = str(idA) + str(idB) + str(pkB1x) + str(pkB1y)
        #return int(hashlib.sha256(mega_string.encode()).hexdigest(), 16) % self.Q
        hash_bytes = keccak(mega_string.encode())
        return int.from_bytes(hash_bytes, byteorder='big') % self.Q

    def message_to_binary(self, message):
        utf8_bytes = message.encode('utf-8')
        binary_string = ''.join(format(byte, '08b') for byte in utf8_bytes)
        return binary_string
    
    def hex_to_ascii(self, hex_string):
        if hex_string.startswith('0x'):         # Drop the 0x prefix
            hex_string = hex_string[2:]
        ascii_str = ''
        for i in range(0, len(hex_string), 2):  # Convert to ASCII
            hex_pair = hex_string[i:i+2]
            char_code = int(hex_pair, 16)
            ascii_str += chr(char_code)
        return ascii_str

    def key_generate(self):
        # Person A (Content Owner)
        self.a_x = random.randint(0, self.Q-1)
        self.a_y = random.randint(0, self.Q-1)
        self.a_xP = self.a_x * self.P
        self.a_yP = self.a_y * self.P

        # Person B (User)
        self.b_x = random.randint(0, self.Q-1)
        self.b_y = random.randint(0, self.Q-1)
        self.b_xP = self.b_x * self.P
        self.b_yP = self.b_y * self.P

        # Ephemeral Randomness
        self.c = random.randint(0, self.Q-1)

        # Sigma Length (hard coded to 256 for this example)
        self.l_bits = 128

    def encrypt(self, message):
        # Compute C1 = r * p
        #sigma = random.randint(0, self.Q-1)
        sigma = random.randint(0, 2 ** 128)
        r = self.hash1(message, sigma, self.id_a, self.a_xP.x(), self.a_yP.x()) 
        c1 = r * self.P
        
        # Compute C2 = skA^-1 * c * r * (pkA1 + pkA2) * P = skA^-1 * fQa
        f = self.c * r
        Qa = (self.a_xP.x() + self.a_yP.x()) * self.P
        fQa = f * Qa
        c2 = inverse_mod(self.a_x, self.Q) * fQa
        
        # Convert the message into binary
        message_in_binary = self.message_to_binary(message)
        self.n_bits = len(message_in_binary)

        # Convert sigma into binary
        sigma_in_binary = bin(sigma)[2:].zfill(self.l_bits)
        
        # Concatenate the message and sigma
        message_plus_sigma = message_in_binary + sigma_in_binary
        
        # Compute H2(fQa)
        hashed_fQa = self.hash2(self.l_bits + self.n_bits, fQa.x())
        
        # C3 = (message || sigma) ^ H2(fQa)
        c3 = ''.join(str(int(a) ^ int(b)) for a, b in zip(message_plus_sigma, hashed_fQa))
        
        # C4 = t * P
        t = random.randint(0, self.Q-1)
        c4 = t * self.P

        # C5 = t + c * r * (pkA1 + pkA2) * skA^-1
        hash3 = self.hash3(c1.x(), c2.x(), c3, c4.x())
        c5 = t + self.c * r * (self.a_xP.x() + self.a_yP.x()) * inverse_mod(self.a_x, self.Q) * hash3

        return c1, c2, c3, c4, c5

    def decrypt(self, c1, c2, c3, c4, c5):
        # Compute points for Decryption check
        c5p = c5 * self.P
        hash3 = self.hash3(c1.x(), c2.x(), c3, c4.x())
        verification_point = c4 + (hash3 * c2)
            
        # C5 * P must equal C4 + H3(C1, C2, C3, C4) * C2
        if c5p.x() != verification_point.x():
            print("Decrypt Check 1 failed!")
            exit(0)
        
        # Compute H2(fQa)
        hash_input = self.a_x * c2
        hash2 = self.hash2(self.l_bits + self.n_bits, hash_input.x())
        
        # (message || sigma) = C3prime ^ hash2
        message_plus_sigma = ''.join(str(int(a) ^ int(b)) for a, b in zip(c3, hash2))
        
        # Extract the message
        message_in_binary = message_plus_sigma[:-self.l_bits]
        message = self.hex_to_ascii(hex(int(message_in_binary, 2)))
        
        # Extract sigma
        sigma_in_binary = message_plus_sigma[-self.l_bits:]

        # Compute point for Decryption check
        r = self.hash1(message, int(sigma_in_binary, 2), self.id_a, self.a_xP.x(), self.a_yP.x())
        addedPoints = self.a_xP.x() + self.a_yP.x()
        Qa = addedPoints * self.P 
        verification_point_2 = inverse_mod(self.a_x, self.Q) * self.c * r * Qa
        
        # C2 must equal skA^-1 * c * r * (pkA1 + pkA2) * P
        if (c2.x() != verification_point_2.x()):
            print("Decrypt Check 2 failed!")
            exit(0)
        
        return message

    def rekeygenerate(self): 
        s = self.hash4(self.id_a, self.id_b, self.b_xP.x(), self.b_yP.x())
        s_inverse = inverse_mod(s, self.Q)
        
        # Compute re-encryption keys
        rk1 = s_inverse * self.c * self.a_xP.x() % self.Q
        rk2 = s_inverse * self.c * self.a_yP.x() % self.Q
        rk3 = s_inverse * (self.a_xP.x() + self.a_yP.x()) % self.Q
        
        return rk1, rk2, rk3
        
    def reencrypt(self, rk1, rk2, rk3, c1, c2, c3, c4, c5):
        # Compute points for Re-Encryption check
        c5p = c5 * self.P
        hash3 = self.hash3(c1.x(), c2.x(), c3, c4.x())
        verification_point = c4 + (hash3 * c2)
        print("C5P:", c5p.x())
        # C5 * P must equal C4 + H3(C1, C2, C3, C4) * C2
        if c5p.x() != verification_point.x():
            print("Re-Encrypt Check 1 failed!")
            exit(0)

        # Compute re-encrypted ciphertexts
        C1prime = c1 * rk1
        C2prime = c1 * rk2
        C3prime = c3
        C4prime = c1 * rk3
       
        return C1prime, C2prime, C3prime, C4prime
    
    def redecrypt(self, C1prime, C2prime, C3prime, C4prime):        
        # Manually compute public key points
        skPrX = self.b_x * self.P
        skPrY = self.b_y * self.P

        # Hash the 2 IDs and both public keys
        s_prime = self.hash4(self.id_a, self.id_b, skPrX.x(), skPrY.x())

        # Compute H2(s'(C1' + C2')) == H2(fQa)
        hash2_input = s_prime * (C1prime + C2prime)
        hash2 = self.hash2(self.l_bits + self.n_bits, hash2_input.x())
        
        # (message || sigma) = C3prime ^ hash2
        message_plus_sigma = ''.join(str(int(a) ^ int(b)) for a, b in zip(hash2, C3prime))
        
        # Extract the message
        message_in_binary = message_plus_sigma[:-self.l_bits]
        message = self.hex_to_ascii(hex(int(message_in_binary, 2)))

        # Extract sigma
        sigma_in_binary = message_plus_sigma[-self.l_bits:]
        
        # Compute point for Re-Decryption check
        r = self.hash1(message, int(sigma_in_binary, 2), self.id_a, self.a_xP.x(), self.a_yP.x()) 
        verification_scalar = r * inverse_mod(s_prime, self.Q) * (self.a_xP.x() + self.a_yP.x())
        verification_point = verification_scalar * self.P
        
        # C4' must equal (s')^-1 * r * (pkA1 + pkA2) * P
        if C4prime.x() != verification_point.x() :
            print("Re-Decrypt Check failed!")
            exit(0)

        return message
    
def main():
    ec = EncryptedCommunication()
    message = input("Enter a message to encrypt: ")
    ec.key_generate()
    c1, c2, c3, c4, c5 = ec.encrypt(message)
    print("Decrypted Message:", ec.decrypt(c1, c2, c3, c4, c5))
    rk1, rk2, rk3 = ec.rekeygenerate()

    print("C1:", c1.x())
    print("C2:", c2.x())
    print("C3:", c3)
    print("C4:", c4.x())
    print("C5:", hex(c5))

    print("RK1:", rk1)
    print("RK2:", rk2)
    print("RK3:", rk3)

    C1prime, C2prime, C3prime, C4prime = ec.reencrypt(rk1, rk2, rk3, c1, c2, c3, c4, c5)

    print("C1':", C1prime.x())
    print("C2':", C2prime.x())
    print("C3':", C3prime)
    print("C4':", C4prime.x())

    print("Re-Decrypted Message:", ec.redecrypt(C1prime, C2prime, C3prime, C4prime))
   
if __name__ == "__main__":
    main()
