# Franklin-last-words [349pts]
This challenge requires a little bit of mathematics to solve it.
Here the flag is encoded character per character using RSA cryptosystem. But there's a twist to it as we can see in the encryption code.

````
def  encrypt_message(m):
	return  pow(m,e,N)
def  advanced_encrypt(a,m):
	return  encrypt_message(pow(a,3,N)+(m <<  24))
e =  3
p =  getStrongPrime(512)
q =  getStrongPrime(512)
#generate secure keys
result =  0
while (result !=1):
	p =  getStrongPrime(512)
	q =  getStrongPrime(512)
	result =  gcd(e,(p-1)*(q-1))
N = p * q
print("N = "  +  str(N))
print("e = "  +  str(e))
rand =  bytes_to_long(get_random_bytes(64))
ct =  []
ct.append(encrypt_message(rand <<  24))
for car in  FLAG:
ct.append(advanced_encrypt(car,rand))
print("ct = "+str(ct))
````
So the code first generates a random number and encode the result of its left shift by 24 using the RSA scheme, let's call the result K  ($K = (rand*2^{24})^3 mod N)$ .After that, it encodes every character of the flag using the advanced_encrypt function. So for a character p, we get $c = (a^3+rand*2^{24})^3 mod N ...(1)$
Note that : $x << 24 = x*2^{24}$.
So if we find rand, we can generate a dictionnary of every character and its encryption and use it to decode the ciphertext.
````
dictionnary_decipher = {advance_encrypt(p,rand):p}
#and to obtain the orginal character p  know it's cipher c we simply do
p = dictionnary_decipher[c]
````
That being said, let's do some math to find rand.
First and for the sake of simplicity, we replace $a^3$ with $b$ and $rand*2^{24}$ with $r$ and then let's develop the equation (1) we obtain :
$c = ( b^3 +3b^2r +3r^2b+r^3 ) mod N$
knowing that $r^3 =K =ct[0]$
we get $c = ( b^3 +3b^2r +3r^2b+K)mod N$
so
$ct[1] = (ord(C)^9 +3*ord(C)^6*r+3*r^2*ord(C)^3+K)mod N ...(2)$ and
$ct[2] = (ord(y)^9 +3*ord(y)^6*r+3*r^2*ord(y)^3+K)mod N ...(3)$
=>
$(ct[1]-K-ord(C)^9)*3^{-1}*(ord(C)^3)^{-1} =C1= (ord(C)^3*r+r^2)mod N ...(2)$ and
$(ct[2]-K-ord(y)^9 )*3^{-1}*(ord(y)^3)^{-1} =C2= ((ord(y)^3)*r+r^2)mod N ...(3)$
=>
$C1 - C2 = ((ord(y)^3)-(ord(y)^3)*r) mod N$
$C1 - C2 = ((ord(C)^3)-(ord(y)^3)*rand*2^{24}) mod N$
=>
$(C1 - C2)*(ord(C)^3−ord(y)^3)^{-1} = (rand*2^{24}) mod N = r$ ( since r << N)
so rand = r >> 24
and bingo, all we have to do know is construct a dictionnary and match every encrypted character with it's original form.

Here's the full exploit :
````

def  encrypt_message(m):
	return  pow(m,e,N)
def  advanced_encrypt(a,m):
	return  encrypt_message(pow(a,3,N)+(m <<  24))
K = ct[0]
#Recovering rand
i_24 =  inverse(2**(24*3),N)
C0_3 = (ord('C')**3)%N
C1_3 = (ord('y')**3)%N
inverse_C1_3 =  inverse(C1_3,N)
inverse_C0_3 =  inverse(C0_3,N)
inverse_3 =  inverse(3,N)
C0 = ct[1] - C0_3**3  - K
C1 = ct[2] - C1_3**3  - K
C0 = (C0*inverse_C0_3*inverse_3)%N
C1 = (C1*inverse_C1_3*inverse_3)%N
inverse_C1_C0 =  inverse(C0_3-C1_3,N)
C = C0-C1%N
r = C*inverse_C1_C0%N
rand = r>>24  # right shift the result to get the number rand

#checking
assert(r**3%N == K)
assert(encrypt_message(rand <<  24)  == ct[0])

#building the dictionnary
dicti = {advanced_encrypt(ord(a), rand):a for a in alphabets}
flag =  ""
for c in ct[1:]: #ct[0] being K
	flag+=dicti[c]
print(flag)
#CyberErudites{Fr4nkl1n_W3_n33d_an0th3R_S3450N_A54P}
````

