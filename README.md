# pluto
pluto - A Tor Hidden Service SMTP Relay using ORB.
Tested with [Mini Mailer](https://github.com/Ch1ffr3punk/mmg) and [smtpdump](https://github.com/Ch1ffr3punk/smtpdump).

The genkeys folder contains a small utility to create the keypair for ORB usage.  

TLS certificates can be created with openssl.  
$ openssl req -nodes -new -x509 -keyout key.pem -out cert.pem  

An ORB is an Onion Reply Block, allowing you to hide your real    
.onion email address, like Mixminion and the Nym Mixnet does    
with SURBS.

You only need to give others your ORB block, so that others  
can use it as reply block, to send you messages.  

An ORB looks like this:

```
::  
qr7cjQXe/7YsmbBhSLzOalGGJeCoGz9YzmDLwKWwp3fkBGMjGYYTLMGG0VPwTzBJ  
sYtSQzYtZSXOCL5owEBhP9xsgnFA1dGjpKQnJYa9MMdLVe/sB2DFdrlbun2HoCvw  
t64o+4rI90zRM5pz1QzkBWOKuDSFkH4btNn6I/fyt6kmGxUzFzb93DvDCnfNyQ==  
::  
```
You simply use [minicrypt](https://github.com/Ch1ffr3punk/minicrypt) to encrypt your .onion email address  
with the server's public key and then add the markers.  

This is how a demo message looks like:

```
From: Mini Mailer <bounce.me@mini.mailer.msg>  
To: orb@pluto.onion  

::  
qr7cjQXe/7YsmbBhSLzOalGGJeCoGz9YzmDLwKWwp3fkBGMjGYYTLMGG0VPwTzBJ  
sYtSQzYtZSXOCL5owEBhP9xsgnFA1dGjpKQnJYa9MMdLVe/sB2DFdrlbun2HoCvw  
t64o+4rI90zRM5pz1QzkBWOKuDSFkH4btNn6I/fyt6kmGxUzFzb93DvDCnfNyQ==  
::  

Hello World! :-)  

This is a test with an ORB.  

Regards  
Stefan  
```
And this is how it looks when the message arrived:  
```
Received: from localhost (kubernetes.docker.internal. [127.0.0.1])  
        by iria (SMTPDump) with SMTP  
        for <pollux@fswlpxkp6xdrwrcu3dmby4lwv4z22bep32s3f3ffrua3x4bmvdyhg2ad.onion>;  
        Sat, 24 May 2025 23:54:50 +0200 (CEST)  
From: orb@pluto.onion  
To: pollux@fswlpxkp6xdrwrcu3dmby4lwv4z22bep32s3f3ffrua3x4bmvdyhg2ad.onion  

Hello World! :-)  

This is a test with an ORB.  

Regards  
Stefan
```
To test an ORB with others, you can send me an anonymous email. :-)

My ORB:
```
::  
AO1lRndxWq2hH1nfbjoHjakC/TaiK2S1iuWwGpw6rAFXooEbQPswopGfUNww9vch
oonjpwr4I9/yXgQRUfGHtPIJAKA0STC+lTSAjp5JJZi7XIfnCF4hnxDpDTxe8kDI
O9fh4Mbq//alEz1S055+9/9APxyeuGzm386hEmHHNSFEMnkCRv6DLVydasNI
::
```
My pluto smtp relay (24/7) and it's public minicrypt key:   
```
rkucect2x3hi3xgibytohtjbmextaacqpxvvqp6eyxu4bi2i7jxupjyd.onion  
Port: 2525

-----BEGIN PUBLIC KEY-----
d+u+KtHqtOD5tBopn1F602rLnGh2wLi+QOdqOolJFlo=
-----END PUBLIC KEY-----
```

If you like pluto, as much as I do, for Tor usage, consider a small donation.    
```  
BTC: 129yB8kL8mQVZufNS4huajsdJPa48aHwHz  
Nym: n1yql04xjhmlhfkjsk8x8g7fynm27xzvnk23wfys  
XMR: 45TJx8ZHngM4GuNfYxRw7R7vRyFgfMVp862JqycMrPmyfTfJAYcQGEzT27wL1z5RG1b5XfRPJk97KeZr1svK8qES2z1uZrS
```




