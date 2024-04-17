import ecdsa
from ecdsa.curves import SECP256k1
import random
import hashlib
import math
from sympy import mod_inverse

c1_point = None

class EncryptedCommunication:
    def __init__(self):
        self.curve = SECP256k1
        self.Q = int(self.curve.order)
        self.G = self.curve.generator
        self.id = 1234
        self.idb = 4321
        self.x = None
        self.y = None
        self.xP = None
        self.yP = None
        self.bx = None
        self.by = None
        self.bxP = None
        self.byP = None

    def message_to_binary(self, message):
        utf8_bytes = message.encode('utf-8')
        binary_string = ''.join(format(byte, '08b') for byte in utf8_bytes)
        return binary_string
    
    def hex_to_ascii(self, hex_string):
        if hex_string.startswith('0x'):
            hex_string = hex_string[2:]
        ascii_str = ''
        for i in range(0, len(hex_string), 2):
            hex_pair = hex_string[i:i+2]
            char_code = int(hex_pair, 16)
            ascii_str += chr(char_code)
        return ascii_str

    def key_generate(self):
        self.x = random.randint(0, self.Q-1)
        self.y = random.randint(0, self.Q-1)
        self.xP = self.x * self.G
        self.yP = self.y * self.G
        self.bx = random.randint(0, self.Q-1)
        self.by = random.randint(0, self.Q-1)
        self.bxP = self.bx * self.G
        self.byP = self.by * self.G

    def encrypt(self, m):
        # Outside of smart contract, use points as integers and then on smart contract use elliptic curves
        
        # Solidity: Use random values for c1 to c4, and for rk1 to rk3,
        #     1  do normal multiplication
        #     2  convert c1 to c4, and scalar multiply with rk1 to rk3
        
        global c1_point
        x_inverse = mod_inverse(self.x, self.Q)
        c = random.randint(0, self.Q-1)
        sigma = random.randint(0, self.Q-1)
        l_bits = math.ceil(math.log2(sigma+1))
        t = random.randint(0, self.Q-1)

        mega_string = m + str(sigma) + str(self.id) + str(self.xP) + str(self.yP)
        # Modulo the string, not hash
        r = int(int(hashlib.sha256(mega_string.encode()).hexdigest(), 16) % self.Q) 
        f = (c * r) #% self.Q        % Q not necessary
        c1_point = r * self.G
        c1 = c1_point.x() 
        #Qa = ((self.G.x()% self.Q) * ((self.xP.x() % self.Q) + (self.yP.x() % self.Q))) % self.Q # not necessaru
        Qa = ((self.G.x()) * ((self.xP.x()) + (self.yP.x()))) 
        #c2 = (f * Qa * (x_inverse % self.Q)) % self.Q
        c2 = (f * Qa * x_inverse)

        binary_message = self.message_to_binary(m)
        sigma_binary = bin(sigma)[2:]
        concat = binary_message + sigma_binary
        fQa = (f * Qa) % self.Q

        hashed_fQa = hashlib.sha256(str(fQa).encode()).digest()
        hashed_fQa_int = int.from_bytes(hashed_fQa, byteorder='big')
        hashed_fQa_mod_Q = hashed_fQa_int % self.Q
        binary_hashed_fQa = bin(hashed_fQa_mod_Q)[2:].zfill(self.Q.bit_length())
        
        max_length = max(len(concat), len(binary_hashed_fQa))
        concat_padded = concat.ljust(max_length, '0')
        binary_hashed_fQa_padded = binary_hashed_fQa.ljust(max_length, '0')
        #print("test", binary_hashed_fQa_padded)
        
        result_binary = ''.join(str(int(a) ^ int(b)) for a, b in zip(concat_padded, binary_hashed_fQa_padded))
        
        c3 = result_binary
        
        c4_point = t * self.G
        c4 = c4_point.x()
        
        mega_string2 = str(c1) + str(c2) + str(int(c3, 2)) + str(c4)
        hash3 = int(hashlib.sha256(mega_string2.encode()).hexdigest(), 16) 
        #c5 = (t % self.Q) + ((c % self.Q) * (r % self.Q) * (int(self.xP.x() % self.Q) + int(self.yP.x() % self.Q)) * (x_inverse % self.Q) * (hash3% self.Q)) 
        # Point addition
        c5 = (t) + ((c) * (r) * (int(self.xP.x() ) + int(self.yP.x() )) * (x_inverse) * (hash3% self.Q)) 

        return c1, c2, c3, c4, c5, l_bits, result_binary, c

    def decrypt(self, c1, c2, c3, c4, c5, l_bits, result_binary):
        # Check for valid ciphertext still has to be implemented.
        c5_times_p = c5 * self.G
        c5p = c5_times_p.x() % self.Q
        
        mega_string2 = str(c1) + str(c2) + str(int(c3, 2)) + str(c4)
        hash3 = int(hashlib.sha256(mega_string2.encode()).hexdigest(), 16)
        #hash3 = ((hash3%self.Q * c2%self.Q) + c4%self.Q) % self.Q
        hash3 = (((hash3%self.Q) * c2) + c4) % self.Q
        
        print("c5p", c5p)
        print("hash", hash3)
        if c5p == hash3:
            print("same")
        else:
            print("not same")
        
        temp = ((self.x * c2) % self.Q)
        hashed_temp = hashlib.sha256(str(temp).encode()).digest()
        binhashfQa = ''.join(format(byte, '08b') for byte in hashed_temp)
        
        max_length = max(len(result_binary), len(binhashfQa))

        result_binary_padded = result_binary.ljust(max_length, '0')
        binhashfQa_padded = binhashfQa.ljust(max_length, '0')
        
        result = ''.join(str(int(a) ^ int(b)) for a, b in zip(result_binary_padded, binhashfQa_padded))
        print("Decryption Result:", result)
        result = result[:-l_bits]
        print("Decryption Result:", result)
        # Second check to see if ciphertext is valid still has to be added

        return self.hex_to_ascii(hex(int(result, 2)))

    def rekeygenerate(self, c):
        mega_string = str(self.id) + str(self.idb) + str(self.bxP.x()) + str(self.byP.x())
        s = int(hashlib.sha256(mega_string.encode()).hexdigest(), 16) % self.Q
        s_inverse = mod_inverse(s, self.Q)
        rk1 = (s_inverse * c * self.bxP.x()) % self.Q
        rk2 = (s_inverse * c * self.byP.x()) % self.Q
        rk3 = (s_inverse * (self.bxP.x() + self.bxP.y())) % self.Q
        
        return rk1, rk2, rk3
        
    def reencrypt(self, rk1, rk2, rk3, c1, c2, c3, c4, c5):
        C1prime = (rk1 * c1) #% self.Q
        C2prime = (rk2 * c1) #% self.Q
        C3prime = c3
        C4prime = (rk3 * c1) #% self.Q
        return C1prime, C2prime, C3prime, C4prime
    
    def redecrypt(self, C1prime, C2prime, C3prime, C4prime, l_bits):
        skPr = self.bx * self.G
        skP = skPr.x() % self.Q
        mega_string = str(self.id) + str(self.idb) + str(self.bxP.x()) + str(self.byP.x())
        s_prime = int(hashlib.sha256(mega_string.encode()).hexdigest(), 16) % self.Q
        sum = (C1prime + C2prime) % self.Q
        sum = (s_prime * sum) % self.Q
        mega_string_2 = str(sum)
        
        hash2 = hashlib.sha256(mega_string_2.encode()).digest()
        binhash2 = ''.join(format(byte, '08b') for byte in hash2)
        
        max_length = max(len(binhash2), len(C3prime))
        
        hash2padded = binhash2.ljust(max_length, '0')
        C3primepadd = C3prime.ljust(max_length, '0')
        
        result = ''.join(str(int(a) ^ int(b)) for a, b in zip(hash2padded, C3primepadd))
        print("Re-Decryption Result:", result)
        result = result[:-l_bits]
        print("Re-Decryption Result:", result)
        
        return self.hex_to_ascii(hex(int(result, 2)))
    
def main():
    ec = EncryptedCommunication()
    message = input("Enter a message to encrypt: ")
    ec.key_generate()
    c1, c2, c3, c4, c5, l_bits, result_binary, c = ec.encrypt(message)
    print("Decrypted Message:", ec.decrypt(c1, c2, c3, c4, c5, l_bits, result_binary))
    rk1, rk2, rk3 = ec.rekeygenerate(c)
    C1prime, C2prime, C3prime, C4prime = ec.reencrypt(rk1, rk2, rk3, c1, c2, c3, c4, c5)
    print("Re-Decrypted Message:", ec.redecrypt(C1prime, C2prime, C3prime, C4prime, l_bits))
    
if __name__ == "__main__":
    main()