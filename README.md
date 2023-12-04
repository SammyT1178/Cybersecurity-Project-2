# Cybersecurity-Project-3

This is a JWKS server using a RESTful HTTP API running on C++. The server runs locally (127.0.0.1:8080). The server generates an RSA key pair, generates a JWT with a unique Key ID, and JWKS list of public keys. These keys are stored and retrieved from an SQLite database.  

Original code provided in and built off of `main.cpp`. 

To run the program, run `make`, then the provided compiled file `jwks_server` can be run. The supplied black box test client `gradebot` is also included to test the server. All tests were run in two seperate Terminal instances using `./jwks_server` and `./gradebot project2` commands respectively.

***NOTE: THIS IS NOT AN OFFICIAL PRODUCT. THIS IS AN UNTESTED PROTOTYPE PROJECT FOR CLASS. PLEASE DO NOT USE IN PROFESSIONAL OR PERSONAL CYBERSECURITY PROJECTS.***

## Results of JWKS Server

### Black Box Results
![alt text](https://media.discordapp.net/attachments/1154202485024620585/1181285719830970439/image.png?ex=6580810e&is=656e0c0e&hm=05591288812c790de3e3853aa9b0fcd6307e21faf39c56a2656e38c2010cf80c&=&format=webp&quality=lossless&width=881&height=391)
### Server Results
![alt text](https://media.discordapp.net/attachments/1154202485024620585/1181285813833703494/image.png?ex=65808125&is=656e0c25&hm=d1807019e82fa594eaa3c10715f15e6715395a011c7ff30a3bc4980fa7f53ed7&=&format=webp&quality=lossless&width=881&height=530)
### Test Suite Coverage (main.cpp)
![alt text](https://media.discordapp.net/attachments/1154202485024620585/1181303514417352794/image.png?ex=658091a1&is=656e1ca1&hm=26950bdeeb1ae8d998ee971b3b688cc8874f560a31827c190c3c5578526175dd&=&format=webp&quality=lossless&width=881&height=137)
