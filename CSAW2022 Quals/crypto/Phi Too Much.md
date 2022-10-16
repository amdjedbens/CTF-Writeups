
## Phi Too Much In Common 228pts
In this challenge we had to pass two levels in order to get the flag.
In the first task, we could request a public key (N,e) and a ciphertext as much as we wanted. After requesting a certain amount of those public keys, we notice that the modulus is often repeated, which leads us to a common modulus attack on the RSA crypto system. 

````
#Step One
from gmpy2 import gcdext, iroot, is_prime
from Crypto.Util.number import *
from pwn import *
r = remote("crypto.chal.csaw.io",5000)
for i in  range(30): #10 repetition will do fine
	r.recvuntil(b"\n> ")
	r.sendline(b"1")
	N = r.recvline().split(b"=")[1].replace(b"\n",b"").replace(b"\r",b"")
	N =  int(N.decode())
	e = r.recvline().split(b"=")[1].replace(b"\n",b"").replace(b"\r",b"")
	e =  int(e.decode())
	c = r.recvline().split(b"=")[1].replace(b"\n",b"").replace(b"\r",b"")
	c =  int(c.decode()) 
	for n in  range(len(Ns)):
	if(Ns[n] == N and es[n] != e):
		gcd,a,b =  gcdext(e, es[n])
		m =  b""
		if(a <  0):
			c =  inverse(c,N)
			m = (pow(c,a,N)*pow(cs[n],b,N))%N
			m =  long_to_bytes(m)
		else:
			c1 =  inverse(cs[n],N)
			m = (pow(c,a,N)*pow(c1,b,N))%N
			m =  long_to_bytes(m)
#d0nt_reUs3_c0mm0n_m0duLus_iN_RSA
````

The second steps we were given the public (e,N) and the private key (d) and we were asked to find the euler totient of N (phi(N)). To calculate phi, we first have to factor N, which is an easy task given the private key d. As explained by Dan Boneh in the section (2.1) common modulus attack in [this paper](http://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf#page=4.).
A better explannation with a working implementation of this attack can be found in Robert Mason answer to this [question](https://crypto.stackexchange.com/questions/6361/is-sharing-the-modulus-for-multiple-rsa-key-pairs-secure/14713) on stackexchange.
````

#credit: Robert Mason on this topic https://crypto.stackexchange.com/questions/6361/is-sharing-the-modulus-for-multiple-rsa-key-pairs-secure/14713
#Returns a tuple (p, q) that are
#the prime factors of N, given an

#RSA key (e, d, N)
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
````
And here's the second part of the exploit
````
#validate the first step
r.recvuntil(b"\n> ")
r.sendline(b"2 d0nt_reUs3_c0mm0n_m0duLus_iN_RSA")

print(r.recv())
print(r.recvline())
N = r.recvline().split(b"=")
if(len(N) != 2): #sometimes the server return an empty line
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
````
