
from Crypto.Util.number import getPrime, bytes_to_long , long_to_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from sage.all import *
import random
# from nth_root import nth_root, chinese_remainder # not provided
from pwn import *

from Crypto.Signature.pss import MGF1
import Crypto.Hash.SHA1
from Crypto.Util.py3compat import bord, _copy_bytes
import Crypto.Util.number
from   Crypto.Util.number import ceil_div, bytes_to_long, long_to_bytes
from   Crypto.Util.strxor import strxor
from Crypto import Random

def _copy_bytes(start, end, seq):
    """Return an immutable copy of a sequence (byte string, byte array, memoryview)
    in a certain interval [start:seq]"""

    if isinstance(seq, memoryview):
        return seq[start:end].tobytes()
    elif isinstance(seq, bytearray):
        return bytes(seq[start:end])
    else:
        return seq[start:end]

def decrypt(ciphertext):
    """Decrypt a message with PKCS#1 OAEP.

    :param ciphertext: The encrypted message.
    :type ciphertext: bytes/bytearray/memoryview

    :returns: The original message (plaintext).
    :rtype: bytes

    :raises ValueError:
        if the ciphertext has the wrong length, or if decryption
        fails the integrity check (in which case, the decryption
        key is probably wrong).
    :raises TypeError:
        if the RSA key has no private half (i.e. you are trying
        to decrypt using a public key).
    """
    _hashObj = Crypto.Hash.SHA1
    
    # See 7.1.2 in RFC3447
    modBits = Crypto.Util.number.size(N)
    k = ceil_div(modBits,8) # Convert from bits to bytes
    hLen = _hashObj.digest_size

    # Step 1b and 1c
    # if len(ciphertext) != k or k<hLen+2:
    #     raise ValueError("Ciphertext with incorrect length.")
    # Step 2a (O2SIP)
    # ct_int = bytes_to_long(ciphertext)
    # Step 2b (RSADP)
    # m_int = self._key._decrypt(ct_int)
    m_int = ciphertext
    # Complete step 2c (I2OSP)
    em = long_to_bytes(m_int, k)
    # Step 3a
    _label = _copy_bytes(None, None, b'')
    lHash = _hashObj.new(_label).digest()
    # Step 3b
    y = em[0]
    # y must be 0, but we MUST NOT check it here in order not to
    # allow attacks like Manger's (http://dl.acm.org/citation.cfm?id=704143)
    maskedSeed = em[1:hLen+1]
    maskedDB = em[hLen+1:]
    # Step 3c
    _mgf = lambda x,y: MGF1(x,y,_hashObj)
    seedMask = _mgf(maskedDB, hLen)
    # Step 3d
    seed = strxor(maskedSeed, seedMask)
    # Step 3e
    dbMask = _mgf(seed, k-hLen-1)
    # Step 3f
    db = strxor(maskedDB, dbMask)
    # Step 3g
    one_pos = hLen + db[hLen:].find(b'\x01')
    lHash1 = db[:hLen]
    invalid = bord(y) | int(one_pos < hLen)
    hash_compare = strxor(lHash1, lHash)
    for x in hash_compare:
        invalid |= bord(x)
    for x in db[hLen:one_pos]:
        invalid |= bord(x)
    # if invalid != 0:
    #     raise ValueError("Incorrect decryption.")
    # Step 4
    return db[one_pos + 1:]

class Server:
    def __init__(self):
        e = 17
        nbits = 512

        p = 9382514633278270465443346284709738118094225353199638128061350340233585086004973186740747832581345199514414312359391866543616758159111090005000882763885927
        # q = 8453449541605579408810782741483850684323035682379984659135454007492925518634509595310733408220923208157313086474832139328922883012191674093040191481661001
        q =13212160867091969072885860506998892026967741482910181684758903257127344052072896121529071925367642577581412110766960946428847335671005432274782151539538093
        
        # getPrime(nbits)
        # p=getPrime(nbits)
        # q = getPrime(nbits)
        N = p * q
        print(N)

        self.p = p
        self.q = q
        self.N = N
        self.e = e
        print(gcd(e,p-1))
        print(p)
        print(gcd(e,q-1))
        print(q)
        self.m = 0
    def encrypt(self, m):
        assert 0 <= m < self.N
        c = pow(m, self.e, self.N)
        self.m = m
        return int(c)

    def decrypt(self, c):
        assert 0 <= c < self.N
        # mp = int(nth_root(c, self.p, self.e))
        # mq = int(nth_root(c, self.q, self.e))
        # m = chinese_remainder([mp, mq], [self.p, self.q])
        p_roots = mod(c, self.p).nth_root(self.e, all=True)
        q_roots = mod(c, self.q).nth_root(self.e, all=True)
        print(p_roots)
        print(q_roots)
        temp = 0
        temp1 = pow(self.m, self.e, self.N)
        for xp in p_roots:
            for xq in q_roots:
                x = crt([Integer(xp), Integer(xq)], [self.p,self.q])
                x = int(x)
                temp2 =pow(x,self.e,self.N)
                temp3 = pow(x,self.e) - pow(self.m, self.e)
                
                print(gcd(temp3,self.N))
                print(gcd(self.N,x-self.m))
                # temp1 = x
                # temp = gcd(x,self.N)
                # print(temp)
                # if temp == self.q or temp == self.p:
                #     break
        return int(temp)
        # return int(m)

    def encrypt_flag(self):
        with open("flag.txt", "rb") as f:
            flag = f.read()

        key = RSA.construct((self.N, self.e))
        cipher = PKCS1_OAEP.new(key)
        c = cipher.encrypt(flag)
        c = bytes_to_long(c)
        return c


async def handle(a):
    S = Server()
    while True:
        cmd = (await a.input("Enter your option (EDF) > ")).strip()
        if cmd == "E":
            m = int(await a.input("Enter your integer to encrypt > "))
            c = S.encrypt(m)
            await a.print(str(c) + '\n')
        elif cmd == "D":
            c = int(await a.input("Enter your integer to decrypt > "))
            m = S.decrypt(c)
            await a.print(str(m) + '\n')
        elif cmd == "F":
            c = S.encrypt_flag()
            await a.print(str(c) + '\n')
            return


# x,y = PolynomialRing(QQ,2,"x,y").gens()
# f = x**17-y**17
# print(f.factor())

e= 17
found = False

while not found:
    r = remote("mc.ax",31370)
    # temp = 1000000000000000000
    temp = 2**61
    
    collectN = []
  
    
    while len(collectN) < 5:
        temp1 = pow(temp,e)
        r.recvuntil("> ")
        r.sendline("E")
        r.recvuntil("> ")
        r.sendline(str(temp))
        temp3 = int(r.recvline().decode())
        if temp3 < temp1:
            collectN.append(temp1 - temp3)
            temp *=2
           
    N = collectN[0]

    for i in collectN[1:]:
        N = gcd(N,i)
    
    for i in range(1,65537):
        fact = gcd(N,i)
        if fact != 1:
            N = N//fact
    
    print("N here")
    print(N)
    if N < 2**1024 and N !=0 and N!= 1:
        r.recvuntil("> ")
        r.sendline("E")
        r.recvuntil("> ")
        r.sendline(str(temp))
        temp1 = int(r.recvline().decode())
        r.recvuntil("> ")
        r.sendline("D")
        r.recvuntil("> ")
        r.sendline(str(temp1))
        temp2 = int(r.recvline().decode())
        temp5 = temp-temp2
        if temp5 <0:
            temp5 = temp2 - temp
        temp3 = gcd(temp5,N)
        temp4 = N//temp3
        cipher = 0
        
        if temp3*temp4 == N and temp3 != N and temp3 != 1:
            print("p here")
            print(temp3)
            print("q here")
            print(temp4)
            r.recvuntil("> ")
            r.sendline("F")
            cipher = int(r.recvline().decode())
            print("cipher here")
            print(cipher)
        
            x = PolynomialRing(GF(temp4),"x").gens()[0]
            p_roots = mod(cipher, temp3).nth_root(e, all=True)
            f = x**17 - cipher
            q_roots = f.roots()
            
            # q_roots = mod(cipher, temp4).nth_root(e, all=True)
            for xp in p_roots:
                for xq,j in q_roots:
                    x = crt([Integer(xp), Integer(xq)], [temp3,temp4])
                    x = int(x)
                    flag = decrypt(x)
                    print(flag)
                    if b"dice" in flag:
                        print(flag)
                        print("yay")
                        found = True
                        break
    r.close()

