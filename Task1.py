import json
from base64 import b16encode
from base64 import b16decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
import hmac
import hashlib

data = b"Accnt:0123456789Accnt:9876543210Descr:1111111111111111111111111111111111111111111111111111111111Amount:123456789" #b indicates that it is a byte literal
key = get_random_bytes(16)

#--------------------------PART 1 ----------------------------------------

#encrypt in ECB mode
def encrypt_message_ECB(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    ciphertext = b16encode(ciphertext_bytes).decode('utf-8')
    return ciphertext

#it is assumed that the key was securely shared beforehand
def decrypt_message_ECB(key, ciphertext):
    try:
        ciphertext = b16decode(ciphertext) #encode the ciphertext using Base16
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext
    except Exception as e:
        print("Incorrect decryption")

ciphertext = encrypt_message_ECB(key, data)
print("The ciphertext using ECB mode is: ", ciphertext)
plaintext = decrypt_message_ECB(key, ciphertext)
print("The plaintext using ECB mode is: ", plaintext)

print("\n------------------------------------------------------------")

#--------------------------PART 2 ----------------------------------------

attacked_ciphertext = ''.join([ciphertext[32:64], ciphertext[0:32], ciphertext[64:]])
attacked_plaintext = decrypt_message_ECB(key, attacked_ciphertext)
print("After the attack, the new plaintext is: ", attacked_plaintext)

print("\n------------------------------------------------------------")

#--------------------------PART 3 ----------------------------------------

def encrypt_message_CBC(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    iv = b16encode(cipher.iv).decode('utf-8')
    ciphertext = b16encode(ciphertext_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ct':ciphertext})
    return result

def decrypt_message_CBC(key, data):
    try:
        b16 = json.loads(data)
        iv = b16decode(b16['iv'])
        ciphertext = b16decode(b16['ct'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext
    except Exception:
        print("Incorrect decryption")

#xor function
def xor(A, B):
    return hex(int(A, 16) ^ int(B, 16))[2:].upper() #[2:] to remove 0x

def attack_CBC(data):
	b16 = json.loads(data)
	ciphertext = b16['ct']
	iv = b16['iv']
	block_to_alter = ciphertext[160:192] #prev block to one containing amount
	byte_to_change = block_to_alter[14:16] #start of amount value
	
	#xor 1st bit of plaintext with the hex value you want in new plaintext
	m = xor('0x31', '0x39') #0x31 is decimal 1, 0x39 is decimal 9
	
	#perform bit flipping
	new_byte = xor(hex(int(m, 16)), hex(int(byte_to_change, 16)))
	while len(new_byte) < 2:
	    new_byte = "".join(['0', new_byte])
	new_ciphertext = ''.join([ciphertext[0:174], new_byte, ciphertext[176:]]) 
	
	result = json.dumps({'iv':iv, 'ct':new_ciphertext})
	return result

ciphertext = encrypt_message_CBC(key, data)
print("The ciphertext using CBC mode is: ", json.loads(ciphertext)['ct'])
plaintext = decrypt_message_CBC(key, ciphertext)
print("The plaintext using CBC mode is: ", plaintext)

#attack on CBC
altered_ciphertext = attack_CBC(ciphertext)
print("\nThe ciphertext after the attack is: ", json.loads(ciphertext)['ct'])
altered_plaintext = decrypt_message_CBC(key, altered_ciphertext)
print("The plaintext after the attack is: ", altered_plaintext)

print("\n------------------------------------------------------------")

#--------------------------PART 4 ----------------------------------------
class AuthenticationError(Exception): pass

def compare_mac(a, b):
    a = a[1:] #since is byte string, start from second element
    b = b[1:]
    different = 0
    
    #Compare using xor to mitigate timing attacks
    for x, y in zip(a, b):
        different |= x ^ y
    return different == 0

#encrypt data with AES-CBC and sign it with HMAC-SHA256
def encrypt_message_CBC_HMAC(plaintext, shared_key, hmac_key):
    plaintext = pad(plaintext, AES.block_size)
    iv_bytes = get_random_bytes(AES.block_size)
    cypher = AES.new(shared_key, AES.MODE_CBC, iv_bytes)
    encrypted_data = cypher.encrypt(plaintext)
    iv = iv_bytes + encrypted_data #secret prefix mac
    signature = hmac.new(hmac_key, iv, hashlib.sha256).digest()
    return (encrypted_data, iv_bytes, signature)

#verify HMAC-SHA256 signature and decrypt data with AES-CBC
def decrypt_message_CBC_HMAC(encrypted_data, iv_bytes, signature, shared_key, hmac_key):
    iv = iv_bytes + encrypted_data
    new_hmac = hmac.new(hmac_key, iv, hashlib.sha256).digest()
    if not compare_mac(new_hmac, signature):
    	print("Incorrect decryption")
        #raise AuthenticationError("message authentication failed")
    cypher = AES.new(shared_key, AES.MODE_CBC, iv_bytes)
    plaintext = cypher.decrypt(encrypted_data)
    return unpad(plaintext, AES.block_size)

hmac_key = get_random_bytes(16)
(encrypted_data, iv_bytes, signature) = encrypt_message_CBC_HMAC(data, key, hmac_key)
print("The ciphertext using CBC mode with HMAC is: ", encrypted_data)
plaintext = decrypt_message_CBC_HMAC(encrypted_data, iv_bytes, signature, key, hmac_key)
print("The plaintext using CBC mode with HMAC is: ", plaintext)

print("\n------------------------------------------------------------")

#--------------------------PART 5 ----------------------------------------

#Replay attack in CBC using HMAC
#in CBC, replay attacks are avoided since each block is encryted in a different way
print("After replay attack in CBC mode using HMAC: ")
altered_ciphertext = b"".join([encrypted_data[32:64], encrypted_data[0:32], encrypted_data[64:]])
decrypt_message_CBC_HMAC(altered_ciphertext, iv_bytes, signature, key, hmac_key)

#Tamper attack in CBC using HMAC
print("After tamper attack in CBC mode using HMAC: ")
iv = b16encode(iv_bytes).decode('utf-8')
ciphertext = b16encode(encrypted_data).decode('utf-8')
ct_json = json.dumps({'iv': iv, 'ct': ciphertext})
altered_ciphertext = attack_CBC(ct_json)
altered_ciphertext = b16decode(json.loads(altered_ciphertext)['ct'])
decrypt_message_CBC_HMAC(altered_ciphertext, iv_bytes, signature, key, hmac_key)
