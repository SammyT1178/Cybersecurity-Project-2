# Cybersecurity-Project-2

This is a JWKS server using a RESTful HTTP API running on C++. The server runs locally (127.0.0.1:8080). The server generates an RSA key pair, generates a JWT with a unique Key ID, and JWKS list of public keys. These keys are stored and retrieved from an SQLite database.  

Original code provided in and built off of `main.cpp`. 

To run the program, run `make`, then the provided compiled file `jwks_server` can be run. The supplied black box test client `gradebot` is also included to test the server. All tests were run in two seperate Terminal instances using `./jwks_server` and `./gradebot project2` commands respectively.

***NOTE: THIS IS NOT AN OFFICIAL PRODUCT. THIS IS AN UNTESTED PROTOTYPE PROJECT FOR CLASS. PLEASE DO NOT USE IN PROFESSIONAL OR PERSONAL CYBERSECURITY PROJECTS.***

## Results of JWKS Server

### Black Box Results
![alt text](https://cdn.discordapp.com/attachments/588868774472450079/1166061173666492496/image.png?ex=65491e18&is=6536a918&hm=f2c7c30e03ec9f48b28a2d03750c2f91fc405ce4091ce881305706c134f78854&)
### Server Results
![alt text](https://cdn.discordapp.com/attachments/588868774472450079/1166061090573144084/image.png?ex=65491e04&is=6536a904&hm=a304c73d5f4fb9a52806fbab885e0579f9f87e5632afcecc3a4c934057ab0fc0&)
### Test Suite Coverage (main.cpp)
![alt text](https://cdn.discordapp.com/attachments/588868774472450079/1166143208955314248/image.png?ex=65496a7e&is=6536f57e&hm=f73bef54333de0eb4a9b8cdcdd16439c8fc63c1ff77a320c696b985f97c5b281&)
