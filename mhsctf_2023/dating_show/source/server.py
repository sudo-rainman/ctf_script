from typing import Any, cast

import base64
import bfv
import pickle
import random
import secret


def send_context(context: bfv.Context):
    print(base64.b64encode(context.to_json().encode('utf-8')).decode('utf-8'))

def recv_ctxts():
    data = input()
    from sys import stderr
    stderr.write(f'{len(data.split(";;"))}')
    for piece in data.split(';;'):
        stderr.write(str(base64.b64decode(piece)))
    return [bfv.Ctxt.from_json(base64.b64decode(piece).decode('utf-8')) for piece in data.split(';;')]


def send_ctxts(data: list[bfv.Ctxt]):
    raw = [base64.b64encode(bytes(ctxt.to_json(), 'utf-8')).decode('utf-8') for ctxt in data]
    print(';;'.join(raw))

def one_round(context: bfv.Context, key: int):
    # These should all technically be polynomials
    sk = bfv.np.poly1d(key)

    # Generate public key/evaluation keys
    context.PubKey(sk)
    context.RelinKeys(sk)
    
    # generate the set of suitors
    my_set = list(random.sample(range(7), k=4))
    my_encrypted_set = [context.encrypt(x) for x in my_set]

    # send the context (including the public key) to Sam
    send_context(context)

    # send Sam the list of suitors
    send_ctxts(my_encrypted_set)
    
    # Get back the protocol result
    result = recv_ctxts()
    assert len(result) == len(my_set) # one result per suitor
    
    intersection = []
    for mine, elem in zip(my_set, result):
        if int(elem.decrypt(sk)(0)) == 0:
            intersection.append(mine)
            
    # Did Sam only pick his valentine?
    return len(intersection) == 1 and intersection[0] == min(my_set)


## Setup: happens before round 1
ptxt_mod = 7
ctxt_mod = (2 ** 35) * ptxt_mod
degree = 1
base = ptxt_mod

# Setting up the encryption context
context = bfv.Context(ptxt_mod, ctxt_mod, degree, base)

print('Welcome to The Blind Date Game!')
for key in secret.keys:
    if one_round(context, key):
        print('You matched with Alex!')
    else:
        print('Bye loser!!!!!')
        break
else:
    print(secret.flag)