from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from math import floor, log
import numpy as np
import utils

poly_to_list = lambda p: list(map(int, p))
@dataclass
class Context:
    ptxt_mod: int
    ctxt_mod: int
    degree: int
    base: int
    bits: int = 0
    poly_mod: np.poly1d = np.poly1d([])
    
    pk: tuple[np.poly1d, np.poly1d] = (np.poly1d([]), np.poly1d([]))
    rlks: list[tuple[np.poly1d, np.poly1d]] = field(default_factory=list)
    
    def to_json(self):
        
        d = asdict(self)
        d['poly_mod'] = poly_to_list(d['poly_mod'])
        d['pk'] = tuple(map(poly_to_list, d['pk']))
        d['rlks'] = [tuple(map(poly_to_list, rlk)) for rlk in d['rlks']]
        return json.dumps(d)
    
    @staticmethod
    def from_json(j):
        d = json.loads(j)
        d['poly_mod'] = np.poly1d(d['poly_mod'])
        d['pk'] = tuple(map(np.poly1d, d['pk']))
        d['rlks'] = [tuple(map(np.poly1d, rlk)) for rlk in d['rlks']]
        return Context(**d)
    
    def __post_init__(self):
        self.poly_mod = np.poly1d([1] + [0] * (self.degree - 1) + [1])
        self.bits = floor(log(self.ctxt_mod, self.base)) + 1
    
    def mod(self, p: np.poly1d):
        return utils.mod(p, self.poly_mod, self.ctxt_mod)
    
        
    def PubKey(self, sk: np.poly1d):
        a = utils.uniform_poly(self.degree, self.ctxt_mod) # should be ctxt_mod
        e = utils.normal_poly(self.degree, self.ctxt_mod)
        self.pk = self.mod(-(a * sk + e)), a
    
    def RelinKeys(self, sk: np.poly1d):
        rlks: list[tuple[np.poly1d, np.poly1d]] = []
        for i in range(self.bits):
            a = utils.uniform_poly(self.degree, self.ctxt_mod)
            e = utils.normal_poly(self.degree, self.ctxt_mod)
            rlk: tuple[np.poly1d, np.poly1d] = (self.mod(-(a * sk) + e + (self.base ** i) * (sk ** 2)), a)
            
            assert self.mod(rlk[0] + rlk[1] * sk - (self.base ** i) * (sk ** 2)) == self.mod(e), f'{rlk}, {sk}, {a}, {e}, {self.base ** i}'
            rlks.append(rlk)
        self.rlks = rlks
    
    def encrypt(self, M: np.poly1d | int):
        u = utils.normal_poly(self.degree, self.ctxt_mod)
        e1 = utils.normal_poly(self.degree, self.ctxt_mod)
        e2 = utils.normal_poly(self.degree, self.ctxt_mod)
        delta = self.ctxt_mod // self.ptxt_mod
        c0 = self.mod(self.pk[0] * u + e1 + (delta * M))
        c1 = self.mod(self.pk[1] * u + e2)
        return Ctxt(val=(c0, c1), ctx=self, rlks=self.rlks)
    
    
    def relin(self, C: tuple[np.poly1d, np.poly1d, np.poly1d]):
        c2_decomp = utils.base_decomp(C[2], self.base, self.ctxt_mod)
        assert len(self.rlks) == len(c2_decomp)
        c0 = self.mod(C[0] + sum(c2_decomp[i] * self.rlks[i][0] for i in range(self.bits)))
        c1 = self.mod(C[1] + sum(c2_decomp[i] * self.rlks[i][1] for i in range(self.bits)))
        return (c0, c1)
    
@dataclass
class Ctxt:
    val: tuple[np.poly1d, np.poly1d]
    ctx: Context
    rlks: list[tuple[np.poly1d, np.poly1d]]
    
    def to_json(self):
        d = asdict(self)
        d['ctx'] = self.ctx.to_json()
        d['val'] = tuple(map(poly_to_list, d['val']))
        d['rlks'] = [tuple(map(poly_to_list, rlk)) for rlk in d['rlks']]
        return json.dumps(d)
        
    @staticmethod
    def from_json(j):
        d = json.loads(j)
        d['ctx'] = Context.from_json(d['ctx'])
        d['val'] = tuple(map(np.poly1d, d['val']))
        d['rlks'] = [tuple(map(np.poly1d, rlk)) for rlk in d['rlks']]
        return Ctxt(**d)
        
        
    
    def __add__(self, other: Ctxt):
        assert other.ctx == self.ctx
        return Ctxt(val=(self.val[0] + other.val[0], self.val[1] + other.val[1]), ctx=self.ctx, rlks=self.rlks)
    
    def __sub__(self, other: Ctxt):
        assert other.ctx == self.ctx
        return Ctxt(val=(self.val[0] - other.val[0], self.val[1] - other.val[1]), ctx=self.ctx, rlks=self.rlks)
    
    def __mul__(self, other: Ctxt):
        assert other.ctx == self.ctx
        
        delta = self.ctx.ptxt_mod / self.ctx.ctxt_mod
        c0 = self.ctx.mod(np.round(delta * self.val[0] * other.val[0]))
        c1 = self.ctx.mod(np.round(delta * (self.val[0] * other.val[1] + self.val[1] * other.val[0])))
        c2 = self.ctx.mod(np.round(delta * self.val[1] * other.val[1]))
        
        return Ctxt(val=self.ctx.relin((c0, c1, c2)), ctx=self.ctx, rlks=self.rlks)
    
    def decrypt(self, sk: np.poly1d):
        delta = self.ctx.ptxt_mod / self.ctx.ctxt_mod
        ptxt = self.ctx.mod(self.val[0] + sk * self.val[1])
        return np.poly1d(np.round(delta * ptxt) % self.ctx.ptxt_mod)