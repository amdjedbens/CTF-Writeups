## Alphasaint

The challenge is speaking about a secret hidden in some store,

![](https://i.imgur.com/41vMwZQ.png)

- As a first procedure when it comes to OSINT challenges, I usually look for information related to the author (his profiles, interests in cybersec, old writeups..) just to grasp an idea how he may think creating the challenges.

- I decided OSINTing the author himself :v
I found out he's a mobile dev as well, with some projects on Google PlayStore.

And this immediately rang a bell for me, so I found the app.

- After installing the AlphaSint application (& downloading the apk file):

![](https://play-lh.googleusercontent.com/4hHArB2BB4Nwh_st5sqrpFRl6b36xLcrDiRQ_6Gbc6X1cSVcRw0doG0-k8mWcA0r_U8=w1024-h768-rw)

- We got a string: **AlphabitIsTheBest1234**, we'll keep it close we may need it later.

Here comes the reversing part:
I used **apktool** firstly, to check smali code first (in simple words SMALI is the intermidiate code coming between Java & DEX file).

	apktool d AlphaSint.apk

![](https://i.imgur.com/QRmAqok.png)

- So we got a variable called: `ENC_FLAG`:

`ZXNJiMMfbNi3VyBW0FZAX/aaW3jclzcwCDK0gmb20pdOO7e8DrBtaf+Tf8Mjs0a620US1mHmVu7UJZyhOC0YHw==`

- Then there's the string: "AlphabitIsTheBest1234", the decryption function computes the SHA-1 digest of the string, then it decrypts the flag  with AES-ECB-PKCS5!

So after writing/testing some code:

    import hashlib

    from Cryptodome.Cipher.AES import MODE_ECB
    from Cryptodome.Cipher import AES
    import base64

    def main():
    	# we got the key from home screen of the application
        key = 'AlphabitIsTheBest1234' 
        ct = base64.b64decode("ZXNJiMMfbNi3VyBW0FZAX/aaW3jclzcwCDK0gmb20pdOO7e8DrBtaf+Tf8Mjs0a620US1mHmVu7UJZyhOC0YHw==")
        aes = AES.new(hashlib.sha1(key.encode()).digest()[:16], MODE_ECB)
        print(aes.decrypt(ct))


    main()
- After running it, "Voilà" we get the flag: 						,			`AlphaCtf{0hh_17_53m5_l1k3_y0u_641n3d_50m3_051n7_4nd_r3v_5k1l5}`