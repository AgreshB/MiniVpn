# MiniVpn
Created a mini VPN using OpenSSL and TUN/TAP interface. Programed in C.

## Technologies Used
- C
- OpenSSL
- Linux VMs


# Intructions For running MiniVPN
- Make sure to have OpenSSL installed on VMs or Linux machine.
- Need to obtain certificates for server and client
    - Followthe instructions in README_cert.md
    - The server machine/VM needs to have these files:
        - server.key
        - server.crt
        - shadow.txt
    - The Client machine/VM needs to have these files:
        - ca.crt
- run make to compile the mainVPN code on both hosts
- Open 2 terminals , for each sever and client

## Follow the following steps in order (First Server then Client)


### On server VM

- After compiling using `make` , run the command ` sudo ./mainVPN -i tun0 -s`  (use -d for debug output)
- It will ask for server certificate password , enter 'passser'
- Server is now running
- On the second terminal run `sudo ip addr add 10.0.1.1/24 dev tun0;sudo ifconfig tun0 up;sudo route add -net 10.0.2.0 netmask 255.255.255.0 dev tun0
`


### On Client VM

- After compiling using `make` , run the command ` sudo ./mainVPN -i tun0 -c 192.168.15.5` (use -d for debug output)
- Youll be promted to enter username and password , currently one user : 'bob' , password : 'hello'
- On the second terminal run `sudo ip addr add 10.0.2.1/24 dev tun0;sudo ifconfig tun0 up;sudo route add -net 10.0.1.0 netmask 255.255.255.0 dev tun0
`
- run `ping 10.0.1.1` to ping server after connection is established