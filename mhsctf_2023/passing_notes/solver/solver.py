from base64 import b64encode,b64decode
from operator import index
from random import choice
from sage.all import GF

b64_alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\\="

field = list(GF(2**6))


def generate_secret_key(n):
  key = 1
  for _ in range(n):
    key *= choice(field)
    key += choice(field)
  return key


def encrypt(message, secret_key):
  message = b64encode(message)
  encrypted = ""
  mod_key = 6 * secret_key**6 + 3 * secret_key**4 + 7 * secret_key**3 + 15
  for char in message:
    encrypted += b64_alpha[field.index(field[b64_alpha.index(chr(char))] *
                                       mod_key)]
  return encrypted


# key = generate_secret_key(10)


cipher = "V4m\GDMHaDM3WKy6tACXaEuXumQgtJufGEyXTAtIuDm5GEHS"
cipher_to_index = [b64_alpha.index(i) for i in cipher]
index_to_field = [field[i] for i in cipher_to_index]

## field[ char index ] * mod_key == index_to_field
possible_mod_key = []
msg = b64encode(b"valentine{")


target = field[b64_alpha.index(chr(msg[0]))]
for i in field:
    if i*target == index_to_field[0]:
        
        possible_mod_key.append(i)

assert len(possible_mod_key) == 1

target = field[b64_alpha.index(chr(msg[1]))]
assert possible_mod_key[0]*target == index_to_field[1]

inv_mod_key = possible_mod_key[0]**(-1)
msg = ""
for i in range(len(index_to_field)):
    msg += b64_alpha[field.index(index_to_field[i]*inv_mod_key)]

print(b64decode(msg))


# print(encrypt(b'[redacted]', key))
