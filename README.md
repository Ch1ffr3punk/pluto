# pluto
pluto - A Tor Hidden Service SMTP Relay using ORB.
Tested with [Mini Mailer](https://github.com/Ch1ffr3punk/mmg) and [smtpdump](https://github.com/Ch1ffr3punk/smtpdump).

The genkeys folder contains a small utility to create the keypair for ORB usage.  

TLS certificates can be created with openssl.  
$ openssl req -nodes -new -x509 -keyout key.pem -out cert.pem  


