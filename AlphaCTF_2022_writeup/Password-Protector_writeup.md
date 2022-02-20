## Password Protector


##### Category: Reverse Engineering
So the challenge talks about getting some hidden secret inside an Android application, let's hope it's not encrypted to cut the suffer.

![](https://i.imgur.com/J1sAaUJ.png)
Disclaimer: I can be mistaken on how flutter works exactly, since I'm no mobile developper and didn't use Flutter before.

Well,
- Firstly I tried with the well-know **apktool** to see what we got in hands:

		apktool d com.alphactf.passwordprotector.apk
    

- I ended realizing it's an android app made with Flutter
	- After googling on how flutter compiles apps, I found out that Flutter compiles in two modes: debug or release mode.
	- Based on the file `kernel_blob.bin`, the app is compiled in debug mode, in which we can find the source code itself.
	- All the app code is at `kernel_blob.bin`, we can `string` it and extract it to a Dart code.
	
	-  In debug mode, you can find the source code itself, with comments. All of the app code is at `kernel_blob.bin`. And you can use strings in order to extract it:

	
    	strings com.alphactf.passwordprotector.apk > extracted_code.dart #android example
- After cleaning a lot of irrelevant strings (imports, void..), we can read the DART code easily.
- To find out this interesting part of code, with a variable named 'fl4g', let's give it a shot.
![](https://i.imgur.com/YEkOuQ2.png)

It was preceded by a list of numbers, I wrote a little python code to execute it and see the results.
 
 // this piece of code is looping through lists elements, apply XOR function to each element with 1337 (e.g: Element1 XOR 1337) then returns the character whose unicode code is the result of XOR.. easy right?
 
    By73l157 = [1400, 1365, 1353, 1361, 1368, 1402, 1389, 1407, 1346, 1367, 1290, 1359, 1290, 1355, 1382, 1292, 1361, 1293, 1355, 1290, 1382, 1293, 1367, 1382, 1293, 1353, 1353, 1382, 1288, 1367, 1382, 1373, 1290, 1371, 1356, 1280, 1382, 1364, 1289, 1373, 1290, 1348]

    print(By73l157)
    flag = ''
    for i in range(0,len(By73l157)):
        flag += Str(chr(By73l157[i]^1337))
    print(flag) 
-  And here we go: `AlphaCTF{n3v3r_5h4r3_4n_4pp_1n_d3bu9_m0d3}`
 
 ##### Side notes:
 - It was really interesting learning some information about how flutter compiles apps, and the fact that we can get back to app source code.


