from base64 import b64encode,b64decode
from z3 import *

from Crypto.Util.number import long_to_bytes
b64_tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
b64_num = [ord(b64_tab[i]) for i in range(len(b64_tab))]

b64_ascii_f = Function('b64_ascii_f', BitVecSort(6), BitVecSort(8))
def b64_ascii(s):
    for i in range(len(b64_tab)):
        s.add(b64_ascii_f(i) == b64_num[i])


def tobin(a):
  return ''.join(format(ord(x), 'b') for x in a)

def to_sextet(msg):
  temp = ""
  for i in msg:
    temp += bin(ord(i))[2:].zfill(8)
  
  while len(temp) %6 != 0:
    temp += "0"

  temp1 = ""
  for i in range(0,len(temp),6):
    temp1 += b64_tab[int(temp[i:i+6],2)]
  return temp1

def sextet_inv(msg):
  temp = ""
  for i in msg:
    # print(bin(b64_tab.index(i)))
    temp += bin(b64_tab.index(i))[2:].zfill(6)
  return temp



# valentine =b"teststringfucktheworld"
# test = ""
# for i in valentine:
#   test += bin(i)[2:].zfill(8)
# print(test)
# a = b64encode(valentine)
# print(a)

# print(sextet_inv(a[:-3].decode()))
######################



# valentine = bytes(input("Valentine: "), "utf-8")
# valentine = b"suckmydickmf"
# a = b64encode(valentine)
# b = b64encode(valentine[::-1])
# print(list(str(a)))
# a = list(map(ord, list(str(a))))
# print(a)
# b = list(map(ord, list(str(b))))

# for j in range(len(a)):
#   print(chr((a[j] + b[j]) % 58 + 65), end='')
# print("")



# cipher = b"WU]Wipuk\cYAvtEXHsRlP_YlPs[UMtVmkcOjupFCVGU"
# cipher = cipher[1:]
# cipher = [i -65 for i in cipher]
# temp = ""
# for i in cipher:
#   temp += bin(i)[2:].zfill(8)

# temp1 = []
# for i in range(0,len(temp),6):
#   temp1.append(int(temp[i:i+6],2))


# init = [BitVec("x"+str(i),8) for i in range(len(temp))]
# rev_init = init[::-1]
# init1 = [(init[i+5] & 0b00100000)+ (init[i+4] & 0b00010000) + (init[i+3] & 0b00001000) + (init[i+2] & 0b00000100) + (init[i+1] & 0b00000010) + (init[i]& 0b00000001) for i in range(0,len(init),6)]
# rev_init1 = [(rev_init[i+5] & 0b00100000)+ (rev_init[i+4] & 0b00010000) + (rev_init[i+3] & 0b00001000) + (rev_init[i+2] & 0b00000100) + (rev_init[i+1] & 0b00000010) + (rev_init[i]& 0b00000001) for i in range(0,len(init),6)]
# s = Solver()

# # b64_ascii(s)
# for i in range(0,len(init),6):
#   s.add(init[i] < 2**0 + 1)
#   s.add(init[i+1] < 2**1 + 1)
#   s.add(init[i+2] < 2**2 + 1)
#   s.add(init[i+3] < 2**3 + 1)
#   s.add(init[i+4] < 2**4 + 1)
#   s.add(init[i+5] < 2**5 + 1)
  


# for i in range(len(init1)):
#   s.add( init1[i] + rev_init1[i] + 65*1== temp1[i] + 58*2)

# print(s.check())
# m = s.model()
# res = ""
#   # temp = m[i+7].as_long()*2**8 + m[i+6].as_long()*2**7 + m[i+5].as_long()*2**6  + m[i+4].as_long()*2**5 + m[i+3].as_long()*2**4 + m[i+2].as_long()*2**3 + m[i+1].as_long()*2**2 + m[i].as_long() 
# for i in range(0,len(init),6):
#   # temp = m[init[i+7]].as_long()*2**7 + m[init[i+6]].as_long()*2**6 + m[init[i+5]].as_long()*2**5  +m[init[i+4]].as_long()*2**4 + m[init[i+3]].as_long()*2**3 + m[init[i+2]].as_long()*2**2 + m[init[i+1]].as_long()*2**1 + m[init[i]].as_long() 
#   a0 = str((m[init[i+5]].as_long() & 0b00100000) >> 5)

#   a1 = str((m[init[i+4]].as_long() & 0b00010000) >>4)
#   a2 = str((m[init[i+3]].as_long() & 0b00001000) >>3)
#   a3 = str((m[init[i+2]].as_long() & 0b00000100) >>2)
#   a4 = str((m[init[i+1]].as_long() & 0b00000010) >>1)
#   a5 = str((m[init[i]].as_long()& 0b00000001))
#   res += a0 + a1 + a2 + a3 + a4 + a5

# # for k in init:
# #   print(m[k].as_long())
# print(long_to_bytes(int(res,2)))






















b = "_f4ce}"[::-1]



b = to_sextet(b)


temp = ""
for i in b:
  temp += bin(b64_tab.index(i) + 65)[2:].zfill(8)



cipher = "WU]Wipuk\cYAvtEXHsRlP_YlPs[UMtVmkcOjupFCVGU"

cipher = "".join(chr(ord(c) - 65 ) for c in cipher).encode()

a = cipher
c = ""
for i in a:
  c += bin(i)[2:].zfill(8)
b = temp*(len(c)//len(b)) + temp[:len(c)%len(b)]

for j in range(5):
  d = ""
  for i in range(0,len(c),8):
    temp = bin((int(c[i:i+8],2)-int(b[i:i+8],2)) % 58  +j*58 )
    d += temp[temp.index("b")+1:].zfill(8)
  e = ""
  for m in range(0,len(d),6):
    temp = bin(int(d[m:m+6],2) - 65)
    e += temp[temp.index("b")+1:].zfill(8)
  try:
    print(long_to_bytes(int(e,2)))
  except:
    pass

for i in range(0,5):
  print(i)
