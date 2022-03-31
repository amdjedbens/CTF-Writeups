# Very Smooth

In this challenge we're given the public key (N,e), the cipher text and the encryotion code.
by the name of the challenge (and the code) we can see that the primes p,q are smooth, so we'll use pollard p-1 algorithm to find them.

Here is the final exploit

```
from Crypto.Util.number import *
import gmpy2
import primefac

n = "c5261293c8f9c420bc5291ac0c14e103944b6621bb2595089f1641d85c4dae589f101e0962fe2b25fcf4186fb259cbd88154b75f327d990a76351a03ac0185af4e1a127b708348db59cd4625b40d4e161d17b8ead6944148e9582985bbc6a7eaf9916cb138706ce293232378ebd8f95c3f4db6c8a77a597974848d695d774efae5bd3b32c64c72bcf19d3b181c2046e194212696ec41f0671314f506c27a2ecfd48313e371b0ae731026d6951f6e39dc6592ebd1e60b845253f8cd6b0497f0139e8a16d9e5c446e4a33811f3e8a918c6cd917ca83408b323ce299d1ea9f7e7e1408e724679725688c92ca96b84b0c94ce717a54c470d035764bc0b92f404f1f5"
c = "1f511af6dd19a480eb16415a54c122d7485de4d933e0aeee6e9b5598a8e338c2b29583aee80c241116bc949980e1310649216c4afa97c212fb3eba87d2b3a428c4cc145136eff7b902c508cb871dcd326332d75b6176a5a551840ba3c76cf4ad6e3fdbba0d031159ef60b59a1c6f4d87d90623e5fe140b9f56a2ebc4c87ee7b708f188742732ff2c09b175f4703960f2c29abccf428b3326d0bd3d737343e699a788398e1a623a8bd13828ef5483c82e19f31dca2a7effe5b1f8dc8a81a5ce873a082016b1f510f712ae2fa58ecdd49ab3a489c8a86e2bb088a85262d791af313b0383a56f14ddbb85cb89fb31f863923377771d3e73788560c9ced7b188ba97"
n = int(n,16)
e = 0x10001
q = primefac.pollard_pm1(n)
p = n//q
phi = (p-1)*(q-1)
d = inverse(e,phi)
print(long_to_bytes(pow(int(c,16),d,n)))
```
