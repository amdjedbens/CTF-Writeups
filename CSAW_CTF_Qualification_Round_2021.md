## [CSAW CTF Qualification Round 2021](https://ctftime.org/event/1315)
- We ([OctaC0re](https://ctftime.org/team/141485)) have ranked 98th (out of ~1200 teams) worldwide.
---
### PoemCollection
	Hey! I made a cool website that shows off my favorite poems. See if you can find flag.txt somewhere!

	http://web.chal.csaw.io:5003

Just changed the GET argument to "../flag.txt"

http://web.chal.csaw.io:5003/poems/?poem=../flag.txt
-> and there you go:
**flag{l0c4l_f1l3_1nclusi0n_f0r_7h3_w1n}**
---
### Crack Me
    Can you crack this?
    Your hash: a60458d2180258d47d7f7bef5236b33e86711ac926518ca4545ebf24cdc0b76c.
    Your salt: the encryption method of the hash.
    (So if the hash is of the word example, you would submit flag{example} to score points.)
	
after identifying with `hash-identifier` we identify it's sha256 with salt so we go on it using the `sha256($salt.$pass)` mode:

` hashcat -m 1420 a60458d2180258d47d7f7bef5236b33e86711ac926518ca4545ebf24cdc0b76c:sha256 rockme.txt`
- we find the following:


        a60458d2180258d47d7f7bef5236b33e86711ac926518ca4545ebf24cdc0b76c:sha256:cathouse

        Session..........: hashcat
        Status...........: Cracked
        Hash.Name........: sha256($salt.$pass)
    
-> So obviously I submitted the following:
**flag{cathouse}**   

---
### Weak Password
    Can you crack Aaron’s password hash?
    He seems to like simple passwords.I’m sure he’ll use his name and birthday in it.
    Hint: Aaron writes important dates as YYYYMMDD rather than YYYY-MM-DD or any other special character separator.
    Once you crack the password, prepend it with flag{ and append it with } to submit the flag with our standard format.
    
    Hash: 7f4986da7d7b52fa81f98278e6ec9dcb

- After running `Hashid` & 'hash-identifier' both leads us to MD5,
so I had to run hashcat with `md5($salt.$pass)` Mode

`hashcat -a 0 -m 20 7f4986da7d7b52fa81f98278e6ec9dcb:Aaron rockme.txt`

we find the following after some attempts: `7f4986da7d7b52fa81f98278e6ec9dcb:Aaron:19800321`

-> Then I easily submitted the following:
**flag{Aaron19800321}**

---
- Those challenges are solved by [Amdj3dax](https://github.com/amdjedbens)  with [OctaC0re](https://ctftime.org/team/141485) team.

