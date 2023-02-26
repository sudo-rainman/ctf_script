import base64
import bfv
import pickle
import pwn
import random
from typing import Any
import numpy as np
import utils

def prod(a) -> bfv.Ctxt:
    if len(a) == 1:
        return a[0]
    mid = len(a) // 2
    return prod(a[:mid]) * prod(a[mid:])


def check_elem(needle: bfv.Ctxt, haystack):
    diffs = [h - needle for h in haystack]
    r = needle.ctx.encrypt(random.randint(1, needle.ctx.ptxt_mod - 1))
    return r * prod(diffs)
    
def recv_context(conn: pwn.remote):
    data = conn.recvline()
    return bfv.Context.from_json(base64.b64decode(data))

def recv_ctxts(conn: pwn.remote):
    data = conn.recvline()
    return [bfv.Ctxt.from_json(base64.b64decode(piece).decode('utf-8')) for piece in data.decode('utf-8').split(';;')]


def send_ctxts(conn: pwn.remote, data):
    raw = [base64.b64encode(bytes(ctxt.to_json(), 'utf-8')).decode('utf-8') for ctxt in data]
    conn.sendline(';;'.join(raw).encode('utf-8'))

###########
poly_mod = np.poly1d([1] + [0] * (1- 1) + [1])
## Setup: happens before round 1
ptxt_mod = 7
ctxt_mod = (2 ** 35) * ptxt_mod
degree = 1
base = ptxt_mod
delta = ctxt_mod // ptxt_mod

def bruteM(ctx,ct):
    ct0 = ct.val[0]
    ct1 = ct.val[1]
    pubkey0 = ctx.pk[0]
    pubkey1 = ctx.pk[1]
    u = 0
    e1 = 0
    e2 = 0
    m= 0
    
    for i in range(-4,5):
        for j in range(-4,5):
            # utils.mod(pubkey0 * u + e1 + (delta * M),poly_mod,ctxt_mod)
            temp = utils.mod(pubkey1 * i + j,poly_mod,ctxt_mod)
            if temp == ct1:
                u = i
                e2 = j
               
                break
    
    
    for i in range(0,7):
        for j in range(-4,5):
            # utils.mod(pubkey0 * u + e1 + (delta * M),poly_mod,ctxt_mod)
            temp = utils.mod(pubkey0 * u + j + (delta * i),poly_mod,ctxt_mod)
            if temp == ct0:
                m =i
                e1 = j

                break
    return m

def one_round(conn: pwn.remote):
    context = recv_context(conn)
    their_set = recv_ctxts(conn)
  
    m = []
    for i in their_set:
        m.append(bruteM(context,i))
    temp = min(m)
    results: list[bfv.Ctxt] = []
    
    for i in m:
        if i == temp:
            results.append(context.encrypt(0))
        else:
            temp1 = i
            while True:
                temp1 = (temp1+1) %7
                if temp1 not in m and temp1 != 0:
                    results.append(context.encrypt(temp1))
                    break
    
    print(m)
    # while True:
    #     my_set_inp = input('Enter four numbers: ').split()
    #     if len(my_set_inp) == 4:
    #         break
        
    # my_set = list(map(int, my_set_inp))
    # my_set_enc = [context.encrypt(x) for x in my_set]
    
    # results: list[bfv.Ctxt] = []
    # for needle in their_set:
    #     results.append(check_elem(needle, my_set_enc))
    
    send_ctxts(conn, results)


host = '0.cloud.chals.io'
port = 29661


with pwn.remote(host, port) as s:
    instructions = s.recvline()
    print(instructions.decode('utf-8'))
    
    for _ in range(10):
        print(_)
        one_round(s)
        
        print(result := s.recvline().decode('utf-8'))
        if not result.startswith('You'):
            print("fail")
            break
    else:
        flag = s.recvline().decode('utf-8')
        print(f'flag: {flag}')

#flag: b'valentine{my_b1g_fr13nd1y_v4l3nt1n3}'
