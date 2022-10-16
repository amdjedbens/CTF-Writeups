# Eddy 470pts

We are provided with the source code of the server and another file implementing the [EDDSA](https://en.wikipedia.org/wiki/EdDSA) Signature Scheme.
The service allows us:
* to sign a message with a random signature key,  
* to sign a message with our signature key,
* and verify the flag by providing the public key (verifying key).

So before we got into the challenge, let's see how the signature and verification algorithms in the edDSA scheme work :
let's call our public key Pk (or verification key) and our private key sk (or signing key). We must also define a Hashing function (in this case it's the Sha512).
#### Signature
````
def  signature(m, sk, pk):
	assert  len(sk) ==  32  # seed
	assert  len(pk) ==  32
	h =  H(sk[:32])
	a_bytes, inter = h[:32], h[32:]
	a =  bytes_to_clamped_scalar(a_bytes)
	r =  Hint(inter + m)
	R = Base.scalarmult(r)
	R_bytes = R.to_bytes()
	S = r +  Hint(R_bytes + pk + m) * a
	e =  Hint(R_bytes + pk + m)
	return R_bytes, S, e
````

1. We generate a number h = H(sk).
2. We convert it to an integer, and call it a.
3. we generate an ephemeral key r = Hint(m) ( a simplified.
4. We generate an ephemeral public key R = r*B (B being the base of the field) and convert it to bytes.
5.  We compute S = r+e*a and e being Hint(R_bytes+pk+m).
Remark:  and return (R,S,e) (normally we wouldn't return e.
#### Verification
````
def  checkvalid(s, m, pk):
	if  len(s) !=  64: raise  Exception("signature length is wrong")
	if  len(pk) !=  32: raise  Exception("public-key length is wrong")
	R =  bytes_to_element(s[:32])
	A =  bytes_to_element(pk)
	S =  bytes_to_scalar(s[32:])
	h =  Hint(s[:32]  + pk + m)
	v1 = Base.scalarmult(S)
	v2 = R.add(A.scalarmult(h))
	return v1 == v2
````
1. Compute h = Hint(Sk+Pk+m)
2. Check if B.Sk = R+h*Pk (R = bytes_to_element(S)).
## The attack
After some googling, we find that the system is vulnerable to fault attack. This means that if we can somehow alter the signature process and obtain a faulty signature, we can easily obtain the public key (Pk). Because we know that:
S = r + a*e and Pk = B.a (the ephemeral key used to encrypt the flag) and e = Hint(R+Pk+m).
so if we can somehow obtain S' = r + e'*a, we can compute a = (S-S')/(e-e').
Luckily, the generation of r doesn't involve the signing key, so we can sign the same message two times, one with the "random" signing key and another time with a signing key we generated.
Here is the full exploit :
````
from pwn import  *
from pure25519.basic import (bytes_to_clamped_scalar,scalar_to_bytes,
bytes_to_scalar,
bytes_to_element, Base)
import hashlib, binascii
from Crypto.Util.number import  *
import os
import json
r=  remote("crypto.chal.ctf.gdgalgiers.com",1000)
  
#getting the message signed by the server public key
r.recvuntil(b"> ")
r.sendline(b"1")
r.recvuntil(b"Enter your message : ")
r.sendline(b"hello")
S1 = r.recvline().replace(b"\n",b"").decode()
SS1  =  int(S1.split(",")[1].split(":")[1])
eS1 =  int(S1.split(",")[2].split(":")[1].replace("}",""))
#getting the same message signed by our own signing key (Sk).
r.recvuntil(b"> ")
r.sendline(b"2")
r.recvuntil(b"Enter your message : ")
r.sendline(b"hello")
print(r.recvuntil(b"Enter your private key : "))
r.sendline(b"113744558270316834126043321099394525334616099854465811344224527827426153721341")
S2 = r.recvline().replace(b"\n",b"").decode()
SS2  =  int(S2.split(",")[1].split(":")[1])
eS2 =  int(S2.split(",")[2].split(":")[1].replace("}",""))
a = ((SS1-SS2)//(eS1-eS2))
A = Base.scalarmult(a)
  
r.sendline(b"3")
r.recvuntil(b"Enter your public key : ")
r.sendline(str(bytes_to_long(A.to_bytes())).encode())
print(r.recv())
#CyberErudites{ed25519_Uns4f3_L1b5}
````