## Getting a self Signed Certificate with OpenSSL
- Copy the configuration file from `/usr/lib/ssl/openssl.cnf`. After copying this file into your current directory, you need to create several sub-directories as specified in the configuration file.
    - For serial , enter a number in the file , all other files can be empty
- For the CA , run :
```
openssl req -new -x509 -keyout ca.key -out ca.crt -config openssl.cnf
```
- For the server , run :
```
openssl genrsa -des3 -out server.key 1024
openssl req -new -key server.key -out server.csr -config openssl.cnf
```
- For the client , run :
```
openssl genrsa -des3 -out client.key 1024
openssl req -new -key client.key -out client.csr -config openssl.cnf
```

- Inorder to sign the certificates , run :
```
openssl ca -in server.csr -out server.crt -cert ca.crt -keyfile ca.key \
             -config openssl.cnf
openssl ca -in client.csr -out client.crt -cert ca.crt -keyfile ca.key \
             -config openssl.cnf

```
