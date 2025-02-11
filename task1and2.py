from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random import random
from Crypto.Hash import SHA256

def add_padding(plaintext : bytes, blocksize=16):
    byte_length = len(plaintext)
    pad_number = blocksize - byte_length % blocksize
    return plaintext + bytes([pad_number]) * pad_number

def rem_padding(plaintext : bytes):
    pad_number = plaintext[-1]
    return plaintext[:-pad_number]


def task1():
    q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    a = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)
    
    # q = bytes.fromhex("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371")
    # a = bytes.fromhex("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5")

    iv = get_random_bytes(16)

    alice = User(a, q, iv)
    bob = User(a, q, iv)


    alice.setSecretandKey(bob.publicKey)
    bob.setSecretandKey(alice.publicKey)

    AliceMsg = "Hi Bob!"
    BobMsg = "Hi Alice!"


    ciphertxtToBob = alice.encryptMsg(AliceMsg)
    ciphertxtToAlice = bob.encryptMsg(BobMsg)


    bobOutput = bob.decryptMsg(ciphertxtToAlice)
    aliceOutput = alice.decryptMsg(ciphertxtToBob)

    print("Task 1:")
    print(f"\tInitialize Bob and Alice with a (too long), q (too long) and iv ({iv})...")
    print(f"\tGenerated Bob and Alices secret and key using their respective publickeys (too long to print)...")
    print("\tAre Bob and Alice's key equal?", (bob.getKey() == alice.getKey()), "\n")
    print("\tAlice Input =", AliceMsg)
    print("\tBob Input =", BobMsg, "\n")
    print("\tCiphertext Bob -> Alice :", ciphertxtToAlice)
    print("\tCiphertext Alice -> Bob :", ciphertxtToBob, "\n")
    print("\tBobs Output after transfer of message and decyption =", bobOutput)
    print("\tAlice Output after transfer of message and decyption =", aliceOutput, "\n")

def task2part1():
    q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    a = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)
    iv = get_random_bytes(16)
    
    alice = User(a, q, iv)
    bob = User(a, q, iv)

    bobs_publicKey = bob.publicKey
    alices_publickey = alice.publicKey

    # Mallory Attack Start

    bobs_publicKey = q
    alices_publickey = q

    # Mallory Attack End

    alice.setSecretandKey(bobs_publicKey)
    bob.setSecretandKey(alices_publickey)

    AliceMsg = "Hi Bob!"
    BobMsg = "Hi Alice!"  


    ciphertxtFromAliceToBob = alice.encryptMsg(AliceMsg)
    ciphertxtFromBobToAlice = bob.encryptMsg(BobMsg)

    bobOutput = bob.decryptMsg(ciphertxtFromAliceToBob)
    aliceOutput = alice.decryptMsg(ciphertxtFromBobToAlice)


    # results of Mallory's attack

    secret = 0 # q^(anything) mod q = 0
    
    hash = SHA256.new()
    byte_length = (secret.bit_length() + 7) // 8
    hash.update(secret.to_bytes(byte_length, byteorder='big'))
        
    key = hash.digest()[0:16]

    cipher1 = AES.new(key, AES.MODE_CBC, iv)
    aliceToBobPlaintext = rem_padding(cipher1.decrypt(ciphertxtFromAliceToBob)).decode('utf-8')
    cipher2 = AES.new(key, AES.MODE_CBC, iv)
    bobToAlicePlaintext = rem_padding(cipher2.decrypt(ciphertxtFromBobToAlice)).decode('utf-8')
    
    print("Task 2 Part 1:")
    print("\tAlice Input =", AliceMsg)
    print("\tBob Input =", BobMsg)
    
    print("\tBobs Output after transfer of message and decyption =", bobOutput)
    print("\tAlice Output after transfer of message and decyption =", aliceOutput)
    print("")
    
    print(f"\tMallory intercepted and decoded \"{aliceToBobPlaintext}\" from the ciphertext being transmitted from Alice to Bob.")
    print(f"\tMallory intercepted and decoded \"{bobToAlicePlaintext}\" from the ciphertext being transmitted from Bob to Alice.\n")

def task2part2():
    q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    # mallorys attack start 
    a = 1
    # mallorys attack end     
    iv = get_random_bytes(16)
    
    alice = User(a, q, iv)
    bob = User(a, q, iv)

    alice.setSecretandKey(bob.publicKey)
    bob.setSecretandKey(alice.publicKey)

    AliceMsg = "Hi Bob!"
    BobMsg = "Hi Alice!"

    ciphertxtFromAliceToBob = alice.encryptMsg(AliceMsg)
    ciphertxtFromBobToAlice = bob.encryptMsg(BobMsg)

    bobOutput = bob.decryptMsg(ciphertxtFromAliceToBob)
    aliceOutput = alice.decryptMsg(ciphertxtFromBobToAlice)

    

    secret = 1 # q^(anything) mod q = 0
    
    hash = SHA256.new()
    byte_length = (secret.bit_length() + 7) // 8
    hash.update(secret.to_bytes(byte_length, byteorder='big'))
        
    key = hash.digest()[0:16]

    cipher1 = AES.new(key, AES.MODE_CBC, iv)
    aliceToBobPlaintext = rem_padding(cipher1.decrypt(ciphertxtFromAliceToBob)).decode('utf-8')
    cipher2 = AES.new(key, AES.MODE_CBC, iv)
    bobToAlicePlaintext = rem_padding(cipher2.decrypt(ciphertxtFromBobToAlice)).decode('utf-8')
    
    print("Task 2 Part 2:")
    print("\tAlice Input =", AliceMsg)
    print("\tBob Input =", BobMsg, "\n")
    print("\tBobs Output after transfer of message and decyption =", bobOutput)
    print("\tAlice Output after transfer of message and decyption =", aliceOutput, "\n")
    print(f"\tMallory intercepted and decoded \"{aliceToBobPlaintext}\" from the ciphertext being transmitted from Alice to Bob.")
    print(f"\tMallory intercepted and decoded \"{bobToAlicePlaintext}\" from the ciphertext being transmitted from Bob to Alice.\n")


class User:
    def __init__(self, a, q : bytes, iv):
        self.a = a
        self.q = q
        self.iv :int = iv

        self.__privateKey = random.randint(0, q-1)
        self.publicKey = pow(a, self.__privateKey, q)
        self.__secret = 0
        self.__key = b""
    
   
    def setSecretandKey(self, partnersPublicKey):
        self.__secret = pow(partnersPublicKey, self.__privateKey, self.q)
        hash = SHA256.new()
        byte_length = (self.__secret.bit_length() + 7) // 8
        hash.update(self.__secret.to_bytes(byte_length, byteorder='big'))
        self.__key = hash.digest()[0:16]
   
    def encryptMsg(self, plaintext : str):
        cipher = AES.new(self.__key, AES.MODE_CBC, self.iv)
        plaintextPadded = add_padding(plaintext.encode('utf-8'), blocksize=16)
        ciphertext = cipher.encrypt(plaintextPadded)
        return ciphertext
    
    def decryptMsg(self, ciphertext : bytearray):
        cipher = AES.new(self.__key, AES.MODE_CBC, self.iv)
        plaintext = rem_padding(cipher.decrypt(ciphertext))
        plaintext = plaintext.decode('utf-8')
        return plaintext
    
    def getKey(self):
        return self.__key
    
    def getSecret(self):
        return self.__secret

task1()
task2part1()
task2part2()
