from math import floor, log
import numpy as np

def uniform_poly(sz: int, mod: int):
    return np.poly1d(np.random.randint(0, mod, sz) % mod)


def normal_poly(sz: int, mod: int):
    return np.poly1d(np.random.normal(0, 2, sz).astype(np.int64))


def base_decomp(p: np.poly1d, base: int, mod: int):
    bits = floor(log(mod, base))
    result = [np.poly1d(np.floor(p / base ** i) % base) for i in range(bits + 1)]
    return result


def mod(p: np.poly1d, poly_mod: np.poly1d, coeff_mod: int):
    return np.poly1d(np.floor(np.polydiv(p, poly_mod)[1]) % coeff_mod)
