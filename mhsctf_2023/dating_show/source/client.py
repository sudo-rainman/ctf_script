import base64
import bfv
import pickle
import pwn
import random
from typing import Any

def prod(a: list[bfv.Ctxt]) -> bfv.Ctxt:
    if len(a) == 1:
        return a[0]
    mid = len(a) // 2
    return prod(a[:mid]) * prod(a[mid:])


def check_elem(needle: bfv.Ctxt, haystack: list[bfv.Ctxt]):
    diffs = [h - needle for h in haystack]
    r = needle.ctx.encrypt(random.randint(1, needle.ctx.ptxt_mod - 1))
    return r * prod(diffs)
    
def recv_context(conn: pwn.remote):
    data = conn.recvline()
    return bfv.Context.from_json(base64.b64decode(data))

def recv_ctxts(conn: pwn.remote):
    data = conn.recvline()
    return [bfv.Ctxt.from_json(base64.b64decode(piece).decode('utf-8')) for piece in data.decode('utf-8').split(';;')]


def send_ctxts(conn: pwn.remote, data: list[bfv.Ctxt]):
    raw = [base64.b64encode(bytes(ctxt.to_json(), 'utf-8')).decode('utf-8') for ctxt in data]
    conn.sendline(';;'.join(raw).encode('utf-8'))


def one_round(conn: pwn.remote):
    context = recv_context(conn)
    their_set = recv_ctxts(conn)
    
    while True:
        my_set_inp = input('Enter four numbers: ').split()
        if len(my_set_inp) == 4:
            break
        
    my_set = list(map(int, my_set_inp))
    my_set_enc = [context.encrypt(x) for x in my_set]
    
    results: list[bfv.Ctxt] = []
    for needle in their_set:
        results.append(check_elem(needle, my_set_enc))
    
    send_ctxts(conn, results)


host = '0.cloud.chals.io'
port = 29661


with pwn.remote(host, port) as s:
    instructions = s.recvline()
    print(instructions.decode('utf-8'))
    
    for _ in range(10):
        one_round(s)
        print(result := s.recvline().decode('utf-8'))
        if not result.startswith('You'):
            break
    else:
        flag = s.recvline().decode('utf-8')
        print(f'flag: {flag}')
