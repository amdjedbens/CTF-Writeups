from math import isqrt, sqrt

import owiener
from Crypto.Util.number import *
from factordb.factordb import FactorDB
from gmpy2 import gcdext, iroot, is_prime
from pwn import *




import random
import fractions
# credit https://crypto.stackexchange.com/questions/6361/is-sharing-the-modulus-for-multiple-rsa-key-pairs-secure/14713
# Returns a tuple (p, q) that are 
# the prime factors of N, given an
# RSA key (e, d, N)
def remove_even(n):
    if n == 0:
        return (0, 0)
    r = n
    t = 0
    while (r & 1) == 0:
        t = t + 1
        r = r >> 1
    return (r, t)
def get_root_one(x, k, N):
    (r, t) = remove_even(k)
    oldi = None
    i = pow(x, r, N)
    while i != 1:
        oldi = i
        i = (i*i) % N
    if oldi == N-1:
        return None #trivial
    return oldi
def factor_rsa(e, d, N):
    k = e*d - 1
    y = None
    while not y:
        x = random.randrange(2, N)
        y = get_root_one(x, k, N)
    p = GCD(y-1, N)
    q = N // p
    return (p, q)


r = remote("crypto.chal.csaw.io",5000)
Ns = []
es = []
cs = []

#Step One
# found = False
# for i in range(30): 
#     r.recvuntil(b"\n> ")
#     r.sendline(b"1")
#     N = r.recvline().split(b"=")[1].replace(b"\n",b"").replace(b"\r",b"")
#     N = int(N.decode())
#     e = r.recvline().split(b"=")[1].replace(b"\n",b"").replace(b"\r",b"")
#     e = int(e.decode())
#     c = r.recvline().split(b"=")[1].replace(b"\n",b"").replace(b"\r",b"")
#     c = int(c.decode())

#     for n in range(len(Ns)):
#         if(Ns[n] == N and es[n] != e):
#             # print()
#             gcd,a,b = gcdext(e, es[n])
#             m = b""
#             if(a < 0):
#                 c = inverse(c,N)
#                 m = (pow(c,a,N)*pow(cs[n],b,N))%N
#                 m = long_to_bytes(m)
#             else:
#                 c1 = inverse(cs[n],N)
#                 m = (pow(c,a,N)*pow(c1,b,N))%N
#                 m = long_to_bytes(m)
#             if(b'd0nt_reUs3_c0mm0n_m0duLus_iN_RSA' == m):
#                 found = True
#                 print("first step banged")
#                 break
#         #d0nt_reUs3_c0mm0n_m0duLus_iN_RSA
#     if(found):break
#     Ns.append(N)
#     es.append(e)
#     cs.append(c)
#validate the first step
r.recvuntil(b"\n> ")
r.sendline(b"2 d0nt_reUs3_c0mm0n_m0duLus_iN_RSA")

print(r.recv())
print(r.recvline())

N = r.recvline().split(b"=")
if(len(N) != 2):
    N = r.recvline().split(b"=")
else:
    N = N[1].replace(b"\n",b"").replace(b"\r",b"")
    N = int(N.decode())

r.recvline()

e = r.recvline().split(b"=")
e = e[1].replace(b"\n",b"").replace(b"\r",b"")
e = int(e.decode())

r.recvline()

d = r.recvline().split(b"=")
d = d[1].replace(b"\n",b"").replace(b"\r",b"")
d = int(d.decode())

p,q =factor_rsa(e, d, N)


phi = (p-1)*(q-1)
print(f"N = {N}")
print(f"phi = {phi}")
print(f"e = {e}")
print(f"d = {d}")

r.recvuntil(b"\n> ")
r.sendline(f"phi {phi}".encode())
print(r.recv())
 




r.close()













# def decrypt(N,e,c):
#     d = owiener.attack(e, N)
#     print(d)
#     ptxt = pow(c, d, N)
#     return long_to_bytes(ptxt)
# N1 = 155471648227927046842865382836864500998248755205461341122544915907816298164002865658000639125201267582161784489542876968361098045512738738952881269938063371062725143620609995675101306354940643245616642457270160032883871244818598016682268206134379883375374958448292366176583086350100730366876828580007862444197
# e1 = 27667570801200742323000213013859673423175823929664862365590810435605551072003
# c1 = 80408830135095736451082576146117291877001919952206720119141844347550886264476784834971586095227397290286055915750311670907025950004770211905396856287717443538562580150097470361321241827529984535460040509120572715524338122860166134337454803142258018669857027745225082169375268354798234882269239992659789906555
# facts = (37,59,163,77755244235856949048560440587640898923853378813039022579921283637942807)

# pq = (N1)%e1
# d = inverse(e1, N1)
# # print(long_to_bytes(pow(c1,d,N1)))

# g,a,b = gcdext(e1, N1)
# print(N1%a)
# print(N1%b)

# print(long_to_bytes(pow(c1,a,N1)))
