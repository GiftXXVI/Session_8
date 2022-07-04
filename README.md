# Managing Passwords

## Option 1: Plaintext
### An Endless Race
- Security is an endless race between developers/security experts and bad actors.
- As soon as a vulnerability is patched, a new exploit arises soon after.

## Risks involved with Plain Text
- When Sending over a network: 
    - Man in the middle attacks: when plain text passwords pass through non-SSL based communication, they are vulnerable to eavesdropping via sniffing tools like Wireshark.
        - Use of SSL does not guarantee safety. SSL stripping attacks can be used to view the plain text passwords flowing through SSL encrypted mediums.
- When Stored in a Database:
    - Plaintext passwords are vulnerable to inside jobs. The stolen plain text passwords can be sold on the black market by disgruntled company employees.
- When Stored in a Backup:
    - A bad actor can attack a backup server and get access to passwords.
- On the front-end application:
    - SQL injection
        - SQL Injection is the placement of malicious code in SQL statements, via web page input.
        - Bad actors can use SQL injection to gain unauthorized access to sensitive data or confidential information.
        - Interactive Demo: [Hacksplaining - SQL Injection](https://www.hacksplaining.com/exercises/sql-injection)



## Option 2: Encryption
### Intro
- From RFC 4949:
    - Encryption: cryptographic (mathematical) transformation of data into a 
        different form that conceals the data's original meaning and prevents 
        the original form from being used.
    - Decryption: a transformation that restores encrypted data to its original form.
- In cryptography, we start with the unencrypted data, referred to as `plaintext`. 
    - `Plaintext` is encrypted into `ciphertext`.
    - `Ciphertext` will in turn (usually) be decrypted back into usable `plaintext`. 

### Types of Cryptographic Algorithms
- Symmetric Encryption: Uses a single key for both encryption and decryption.
    - used for privacy and confidentiality.
- Asymmetric Encryption: Uses one key for encryption and another for decryption. 
    - used for authentication, key exchange ...

### Demos: Using Cryptography
#### Symmetric Encryption (AES)
The following Repl contains this demo: https://replit.com/@GiftXXVI/Demo-1-AES-ENCRYPT?v=1


```python
#import sys
#!{sys.executable} -m pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

data = b'M7_P@55w04D'

session_key = get_random_bytes(16)
cipher = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)
nonce = cipher.nonce
print('Session Key: ', str(session_key))
print('CipherText: ', str(ciphertext))

```

    Session Key:  b'\x16O\xcc\xfd\xd8UHJ^\x08\xb1\xeb\xa4\xe6\xfdF'
    CipherText:  b'Ds\x8dm\xef\x97\xf4Md\x89\xb4'


#### Symmetric Decryption (AES)

The code for this demo is also available at: https://replit.com/@GiftXXVI/Demo-2-AES-DECRYPT?v=1


```python
from Crypto.Cipher import AES

cipher = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
print('Plaintext: ', data)

```

    Plaintext:  b'M7_P@55w04D'


### Asymmetric Cryptography (RSA)

### Key Generation

The code for this demo is also available at: https://replit.com/@GiftXXVI/Demo-3-RSA-KeyGen?v=1


```python
from Crypto.PublicKey import RSA

key = RSA.generate(2048)
# sender
private_key = key
str_private_key = private_key.export_key()

# recipient
public_key = key.publickey()
str_public_key = public_key.export_key()

print('\n Private Key: ', private_key, str_private_key)
print('\n Public Key: ', public_key, str_public_key)

```

    
     Private Key:  Private RSA key at 0x7F6D645B9A50 b'-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxQydVIuQU4WzUIgMUpwhhZVdfTuHtmjxFxUPvHdn0LIxkHPu\n/kQSW8O+4lME+VWnelsLIBN8nE+G1PD3g+51SWD7jWJ+DAYrugvSu2d14BCYmvXV\nyOUK4oodPY/CpnO8WFOZGTsEMWX2nFDFLdatgLr4byiI3TJMf48OZyGiJNNy/ndc\nYNK/rrjSTg4q3dSakEsovnJRrdpyagSyo/riilO00plKsmy+PzDnDrQBEW/fgliI\nZjf7KnRZzJPEukn8KPdvTj9pgECDp+LZAsCKQNSI2/GMjeIt7FckSAEzD5i6E8Cg\nl0v9bduDTV//cCIQjrWwNfYFsDwvsZsbRke9uwIDAQABAoIBABss6dx0FvvTL5oG\no/Rsq0QvXPey0xJOwhkrLW1nkP4Q5Txae3Zo+u3ZlCTFyvomsZ9H7m6GYXlz5Pt5\nyW5SNQNhXa/vtRnWwVxk2bOWHtqU+gbnqovh6AYQLYeE9mpbAc8Ipc+l+lEPEoYX\nrunrISiPdfMWmwbZM1WllsNAZIqWui6NVBGtYILu2CM4Sh9nnkYPs7uLB1+LgVPL\n23vP92AdpWFStSWCcaAZOOvOFGyeSOysUZ7MMhsHY2748LNam6vG40b/iPTUg9jY\nI6GvGF/Y3GZ6TiKFHzt2W9xqqMVYoanhzb7clTFl0glA1mY13SdqvslNHQL3VKH/\nAyUOs1ECgYEA2SicsWm6bpdKTajToUvUi3evyflrPaFzz5FA+ssUN3F3BA4K5sr+\nXsw96tWzoVB2K2BscBFTdaPz/RLGXYdTnPAfLg3MFIn1XtXHWv7S9sWcOjxffr7N\nGZ5A1laRvpCUuxHoea3lkGAQ4M0a73J6FY/TPzLuiIdwQqWnVbjQFwMCgYEA6Es5\nF1w6BrRV5LCLzFG9qH9bX6jcleWXYCUjn8Mzoz/E2MCgS+XuoO/rCP703jpoZYaU\nAlbv64DtMCSx/EmJg2/ycYTNGcrx24Iv/DZckOVjyV59ok5fJzCdFprQ3WEJod0u\nGz4KjSxybBHu6Uorkmz2kIGvzIoPbtYDzvRCROkCgYACd/S4C5Sj9zJQCbBGMB99\namHkMOKoM7KmVGdhsndLXg3VTPeQwhP8LeQyTDWbitedDJ6O85N4TeHTKah5nbU0\nnoIsOtnsDdltN47pmOX7CioJe3A2d6LLPMJN7XQAr5IRQlXbND/c0Uq/03UP7cQ3\nhIgJOuH9SVTcXRe24L/00wKBgEH0mdE4LoGY0oqMViU9UEx3XMpcd8VX2xNBeEv0\ncMT5Zjrk9p6WOpsXg/SZ74zpqJqrC3tek+CaSr5QrPilKJZZQs1Yl6OrK+DXpihG\nhyHc/+g9HA7pkbre4rt4WbWBx+pdkqnJg9VxuUtWDC/RD24T4i5FpFS/HoKp4Yrx\nb5+BAoGBAJsj49QsthRDDZXgORRiR4dTp8R4GGPN0nNXS49DF/ZSSWCBPrDhSwMH\ng3s0+YSxXtDLJyTu69Is11cyXfPJj0iOO4FgG9EIgNWQ0LUUr/o0zcPBIxpeWnyB\n5BxFSRsZrGW+xxbEclckGkdOHl1OOvm7Ak3ognrBPOOo2RIQI/He\n-----END RSA PRIVATE KEY-----'
    
     Public Key:  Public RSA key at 0x7F6D6454AC20 b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxQydVIuQU4WzUIgMUpwh\nhZVdfTuHtmjxFxUPvHdn0LIxkHPu/kQSW8O+4lME+VWnelsLIBN8nE+G1PD3g+51\nSWD7jWJ+DAYrugvSu2d14BCYmvXVyOUK4oodPY/CpnO8WFOZGTsEMWX2nFDFLdat\ngLr4byiI3TJMf48OZyGiJNNy/ndcYNK/rrjSTg4q3dSakEsovnJRrdpyagSyo/ri\nilO00plKsmy+PzDnDrQBEW/fgliIZjf7KnRZzJPEukn8KPdvTj9pgECDp+LZAsCK\nQNSI2/GMjeIt7FckSAEzD5i6E8Cgl0v9bduDTV//cCIQjrWwNfYFsDwvsZsbRke9\nuwIDAQAB\n-----END PUBLIC KEY-----'


### Example: Sending Session Keys

### Sender's End
The code for this demo is also available at: https://replit.com/@GiftXXVI/Demo-4-Send-Key-Using-RSA?v=1


```python
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from json import dumps

# Encrypt Key
cipher_rsa = PKCS1_OAEP.new(public_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt Message
data = b"Today's lottery winning numbers are: 30,36,4,24,81"
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
nonce = cipher_aes.nonce

# Print Sent (Encrypted) Message
message_sent = {"Secret": str(ciphertext), "Key": str(
    enc_session_key), "Nonce": str(nonce)}
print(dumps(message_sent, indent=4, sort_keys=True))

```

    {
        "Key": "b'jZ\\xdb\\x17QHfJ\\xb2\\xdco\\x8aF\"\\\\\\xe9\\x11\\xf5o\\xf2\\xa4r\\xa5\\x17\\x03-\\xbao~\\x15G\\xbf\\t\\xc2\\xd7,\\'R$\\xf8\\xecb\\xdf0\\'J\\xa0\\xd6\\xc4R\\x0f\\x88\\xecM\\xbb&j}\\xd1E\\x99/P]\\xa4\\xcf\\x85\\x81-\\x04}\\x02e\\x1ePg\\xc1\\xa7TfDX\\xefS__VG\\x1b@\\xad\\x9cF\\x90j\\xaa2\\x00\\xbf\\xac\\x84\\xe8\\x81n\\xfb\\tvO\\xf5\\x06\\x06Ax=\\x0c\\xc2\\x98IY\\n\\x04\\xdc\\xf6\\x15\\x1fu\\xc3\\x7f\\x9d\\x95\\xb8L\\x98PJ\\xfc\"{\\xf1#K\\xb9\\x8cb\\xaa+f\\xbe\\xb4\\xef\\x99(\\x91\\xc4p\\xc3\\xaa\\x88\\xa4\\xf0\\x1a\\xfb\\xc0]\\x00\\xca\\x1bW\\xbc\\xfeT\\xa2\\x0ey\\xfc\\xf3\\xfc\\x8f\\xca\\xb4\\xb4\\xe2t\\x1f\\x9bY\\x08<\\xcd\\xd1\\x12\\n\\x86q\\xf3\\x01\\xa76\\t\\x1bC2|Pu\\xcdq\\xe6\\xe2\\xd3-p7\\xfa[0\\xce\\xe8\\xcd\\xb9\\xad\\xca\\x16\\'\\xf3\\xad\\xc3\\xfd\\x80\\xac\\x13C\\xd6\\xc7[[\\x9c\\xce\\x9c\\x1a\\x99\\xf7\\xbc\\xf7X\\xadV\\':\\x815\\x89%3*\\xa6'",
        "Nonce": "b'\\xda$\\x12\\xc5\\\\\\xe1\\x82\\xe3\\xfd\\x8c\\x93\\xfe\\xf8\\xd5\\x01\\x89'",
        "Secret": "b'x\\x92\\xeb\\x11\\x14]\\xde\\x80\\rB\\xca\\xef<\\xd4\\xb6\\x15\\x88[\\xcezg\\x06Gr\\xc1\\xb7\\xbb\\xd8\\xa3\\xcfi\\xcc\\x14\\x03\\'\\xdd\\xff\\xc2\\xc0\\xa7\\xbb\".\\x8a\\xee\\xb1\\x89\\xb8\\x10n'"
    }


### Recipient's End

The code for this demo is also available at: https://replit.com/@GiftXXVI/Demo-5-Receiving-Encrypted-Session-Key?v=1


```python
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from json import dumps

# Decrypt Key
cipher_rsa = PKCS1_OAEP.new(private_key)
decrypted_session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt Message
cipher_aes = AES.new(decrypted_session_key, AES.MODE_EAX, nonce)
plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

# Print Message
message_received = {"Secret": str(plaintext), "Key": str(
    decrypted_session_key), "Nonce": str(nonce)}
print(dumps(message_received, indent=4, sort_keys=True))

```

    {
        "Key": "b'\\x16O\\xcc\\xfd\\xd8UHJ^\\x08\\xb1\\xeb\\xa4\\xe6\\xfdF'",
        "Nonce": "b'\\xda$\\x12\\xc5\\\\\\xe1\\x82\\xe3\\xfd\\x8c\\x93\\xfe\\xf8\\xd5\\x01\\x89'",
        "Secret": "b\"Today's lottery winning numbers are: 30,36,4,24,81\""
    }


### Problem: Brute Force Attack

- A brute force attack uses trial-and-error to guess login info.
- It works by cycling through all possible combinations of letters to try and guess the correct password.
- The amount of time it will take to figure out the correct password depends on the length and complexity of the password.
    - Passwords with more characters take longer to figure out.
    - Passwords with a wider variety of characters (alphabet, numerals, symbols ...) take longer to figure out.

### Demo: Brute Force Attack


```python
import time

chars = ['0','1']
def bruteforce(pin):
    pin_arr = list(pin)
    start = time.perf_counter()
    stop = start
    found = _bruteforce(pin_arr)
    stop = time.perf_counter()
    print(f"Input: {pin}, Time Taken: {stop - start:0.4f} \n")
    return found

def _bruteforce(pin, guess=[]):
    global chars
    if len(guess) > len(pin):
        return None
    else:
        if pin == guess:
            return True
        else:
            for i in range(len(chars)):
                found = _bruteforce(pin, guess + [chars[i]])
                if found:
                    return True
    return False
bruteforce('11')            
bruteforce('1101010101')
bruteforce('11010011010101010')
    
```

    Input: 11, Time Taken: 0.0000 
    
    Input: 1101010101, Time Taken: 0.0064 
    
    Input: 11010011010101010, Time Taken: 0.7399 
    





    True



### Remedy
- Rate limit login attempts
- Do not allow simple passwords
- Log and Monitor attacks
- Implement captchas
- Do not encrypt and store passwords, this leaves the possibility of bad actors decrypting the passwords if they acquire the database.
- Instead, hash the passwords because Hash Algorithms are not reversible.

## Option 3: Hashing

### Hash Function
- A function that maps any string (of any length), to a fixed-length string.

### Cryptographic Hash Function
- A good hash function that also has the **one-way property** and one of the two **collision-free properties**.
- Examples: MD5, SHA-1 
- For hashing passwords, special hash functions that use key derivation functions to slow down brute force attacks are recommended.
    - Examples are: **bcrypt**, **scrypt**, **argon2**

#### One-way Property
- Given a hash function and a hash value, it is hard (i.e., computationally infeasible, "impossible") to figure out the plaintext password.

#### Collision Free Properties
- Given a hash function and a hash value, it is hard (i.e., computationally infeasible, "impossible") to find a different plaintext password that also produces the same hash value.
- Given a Hash function, it is hard (i.e., computationally infeasible, "impossible") to find any pair of passwords that produce the same hash value.

### Demo: Authentication with Argon2



```python
#import sys
#!{sys.executable} -m pip install argon2

from argon2 import PasswordHasher, Type
from argon2.low_level import error_to_str
import argon2

ph = PasswordHasher()

passwd = '5upper_5ecret'
hashed_passwd = ph.hash(passwd)
print("Hashed Password: ",hashed_passwd)
```

    Hashed Password:  $argon2id$v=19$m=65536,t=3,p=4$LeReS2JlG/pgyyz86TsIuQ$WHpsQXU1u5xXp4D07NjUqy8u/RSkX2YqKf1bqRIlI5M



```python
attempts = ['Supper_5ecret','Trial_2', '5upper_5ecret']

def authenticate(passwd):
    try:
        ph.verify(hashed_passwd,passwd)
        print(f"Using Password '{passwd}', Authentication Succeeded!!!")
        return True
    except argon2.exceptions.VerifyMismatchError:
        print(f"Using Password '{passwd}', Error: Authentication Failed!!!")
        #In flask: abort(401)
        return False

for i in attempts:
    authenticate(i)
```

    Using Password 'Supper_5ecret', Error: Authentication Failed!!!
    Using Password 'Trial_2', Error: Authentication Failed!!!
    Using Password '5upper_5ecret', Authentication Succeeded!!!


### Problem: Rainbow Table

- A rainbow table is a precomputed table for caching the output of cryptographic hash functions, usually for cracking password hashes. 
- Tables are usually used in recovering a key derivation function (or credit card numbers, etc.) up to a certain length consisting of a limited set of characters.
- Use of a key derivation that employs a salt makes this attack infeasible. (such as Argon2)

### Remedy: Rainbow Table
- Use of a key derivation that employs a salt makes this attack infeasible.
    - Salting our passwords using a randomly generated string
    - It gets added to the input we want to hash
        - So now instead of pass123 => pass123xyzwty
        - Resulting in a mismatch in the rainbow table

## Resources
- [Internet Engineering Task Force - RFC4949](https://datatracker.ietf.org/doc/html/rfc4949)
- [OWASP - Secure Coding Quick Reference](https://owasp.org/www-pdf-archive/OWASP_SCP_Quick_Reference_Guide_v2.pdf)
- [Hacksplaining - Password Mismanagement - Interactive](https://www.hacksplaining.com/exercises/password-mismanagement)
- [Hacksplaining - Password Management](https://www.hacksplaining.com/prevention/password-mismanagement)
- [Hacksplaining (Youtube) - Man in the Middle Attacks](https://www.youtube.com/watch?v=DgqID9k83oQ)
- [Hacksplaining - SQL Injection - Interactive](https://www.hacksplaining.com/exercises/sql-injection)
- [HTTPS India - How SSL Stripping Works](https://www.https.in/ssl-security/how-ssl-strip-work/)
- [Pycryptodome Docs](https://pycryptodome.readthedocs.io/en/latest/src/examples.html)
- [Kaspersky - Brute Force Attacks](https://www.kaspersky.com/resource-center/definitions/brute-force-attack)
- [Replit - robowolf - Actual Brute Force Attack](https://replit.com/talk/share/Actual-Brute-Force-Password-Cracker/85402)
- [MDN - Recursion](https://developer.mozilla.org/en-US/docs/Glossary/Recursion)
- [Tyler's Guides - Introduction to Cryptography](https://tylersguides.com/introductions/a-simple-introduction-to-cryptography/)
- [argon2-cffi: Argon2 for Python](https://argon2-cffi.readthedocs.io/en/stable/)
- [Replit - Arthur Kalule (Session Lead) - Rainbow Tables Demo](https://replit.com/@KaluleArthur/RainBow-Tables#main.py)
- [Replit - Habib Sentongo (Session Lead) - Hashing With Salt](https://replit.com/@HabibSentongo/SaltedHashing?v=1)
- [Stack Overflow - Argon2](https://stackoverflow.com/questions/58431973/argon2-library-that-hashes-passwords-without-a-secret-and-with-a-random-salt-tha)


```python

```
