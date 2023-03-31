INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	gcc -w -I$(INC) -L$(LIB) mainVPN.c -o mainVPN -lssl -lcrypto -ldl -fpermissive