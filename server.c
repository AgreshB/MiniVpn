#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>

#include <arpa/inet.h> 
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>

#include <memory.h>
#include <signal.h>
#include <termios.h>
#include <netdb.h>
#include <netinet/in.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CLIENT 0
#define SERVER 1

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFFER_SIZE 2000   
#define BUFFER_SIZE_MESSAGE 100
#define BUFFER_SIZE_SMALL 50

// packet related constants
#define PORT 55555
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

// Encryption / SSL related constants
#define CERTF "server.crt"
#define KEYF  "server.key"
#define SHADOW_FILE_PATH "shadow.txt"
#define HMAC_LENGTH 32
#define KEY_LEN 16
#define SEPARATOR ":"
#define SEPARATOR_LEN 1


int server_tcp(int pipe_fd[], int child_pid) {
	int err, temp_socket , server_sd;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	size_t cli_info_size = sizeof(sa_cli);

	SSL_CTX* ssl_context;
	SSL* ssl;
	SSL_METHOD *ssl_m;

	char buf[BUFFER_SIZE];
	unsigned char key[KEY_LEN];
	unsigned char iv[KEY_LEN];
	char user_details[BUFFER_SIZE_SMALL];

	int index = 0;
	int ret = 0;
    do_debug("Checking certificate for server !!\n");   

	// first initialise SSL and create a context
	// and check for Server certificate and private key
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	ssl_m = SSLv23_server_method();
	ssl_context = SSL_CTX_new(ssl_m);
	if (!ssl_context) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	ret = SSL_CTX_use_certificate_file(ssl_context, CERTF, SSL_FILETYPE_PEM);
	if (ret == -1) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	ret = SSL_CTX_use_PrivateKey_file(ssl_context, KEYF, SSL_FILETYPE_PEM);
	if (ret == -1) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ssl_context)) {
		fprintf(stderr, " Certificate of Public Key and current Private key does not match\n");
		exit(4);
	}
    printf("Certificate Check for server done !!\n");   
	
	// Create a TCP socket and bind to port , wait for connections

	temp_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (temp_socket < 0) {
		perror("socket");
		exit(1);
	}
	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(PORT);
	err = bind(temp_socket, (struct sockaddr*) &sa_serv, sizeof(sa_serv));
	if (err < 0) {
		perror("bind");
		exit(1);
	}


	// Listen and connect to client
	if (listen(temp_socket, 5) < 0) {
		perror("listen");
		exit(1);
	}
	//cli_info_size = sizeof(sa_cli);
	server_sd = accept(temp_socket, (struct sockaddr*) &sa_cli, &cli_info_size);
	if (server_sd < 0) {
		perror("accept");
		exit(1);
	}
	close(temp_socket);

	printf("Connected to %lx on port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);


	// initialize SSL connection

	ssl = SSL_new(ssl_context);
	if (ssl == NULL) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}
	SSL_set_fd(ssl, server_sd);
	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}

	// Read the client packet
	// Extract the data from the received buffer

	// Receive the data from client
	int res = SSL_read(ssl, buf, sizeof(buf) - 1);
	if (res <= 0) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}

	// Extract the data from the received buffer 
	// Include KEY and IV , + User details
	index = 0;
	memcpy(&key[0], &buf[index], KEY_LEN);
	index += KEY_LEN;
	memcpy(&iv[0], &buf[index], KEY_LEN);
	index += KEY_LEN;
	int user_cred_len = res - (KEY_LEN * 2);
	memcpy(&user_details[0], &buf[index], user_cred_len);
	index += user_cred_len;
	user_details[user_cred_len] = '\0';
	// Zero out the login info
	memset(buf, 0, BUFFER_SIZE);
	// Decrypt the user details
    do_debug("Checking password received from client\n");
	// Format of user_details should be <username>:<password>
  	char username[BUFFER_SIZE_SMALL];
	memset(username, '\0', sizeof(username));
	char password[BUFFER_SIZE_SMALL];
	memset(password, '\0', sizeof(password));

	// Exrtact user_details
	char* len = strtok(user_details, SEPARATOR);
	strcpy(username, len);
	len = strtok(NULL, SEPARATOR);
	strcpy(password, len);

	int verify = verify_credentials(username,password);
    do_debug("Password Check done\n");

	// verify will actually be 0 , if passowrds match , 
	// thus verify = 0 means authenticated
	// else verify = 1 means not authenticated
	// set buf to match the result	
	buf[0] = 0;
	buf[1] = 1;
	if (verify != 0) {
		buf[1] = 0;
	}
	// send to client the authentication result
	if(SSL_write(ssl, buf, BUFFER_SIZE_MESSAGE) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}
	if (verify != 0) {
		do_debug("Wrong username or password. \n");
		kill(child_pid, SIGKILL);
		exit(1);
	} else {
		printf("User authenticated !\n", verify);
		do_debug("TCP connection established. \n");
	}

	// Send the key to the pipe (UPD process)
	memset(buf, 0, sizeof(buf));
	buf[0] = 1;
	int msg_len =1;
	memcpy(&buf[msg_len],&key[0],KEY_LEN);
	msg_len += KEY_LEN;
	memcpy(&buf[msg_len],&iv[0],KEY_LEN);
	msg_len += KEY_LEN;
	write(pipe_fd[1], buf, BUFFER_SIZE_MESSAGE);
	memset(buf, 0, BUFFER_SIZE);


	// Go to infinite loop to listen to the user control commands that come from the client's TCP process
	sleep(2);
	while (1) {
		printf("Wainting on Client Response :\n");
		// Receive the data from client
		if(SSL_read(ssl, buf, BUFFER_SIZE_MESSAGE) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(2);
		}
		// BONUS SECTION
		// Perform KEY and IV UPDATE
		if (buf[0] == 1) {
			printf("CLIENT requested  KEY and IV UPDATE\n");

			index = 1;
			// copy updated key and iv
			memcpy(&key[0], &buf[index], KEY_LEN);
			index += KEY_LEN;
			memcpy(&iv[0], &buf[index], KEY_LEN);
			index += KEY_LEN;

			// Send the new key to the pipe (to the UDP program)
			buf[0] = 1;
			int msg_len =1;
			memcpy(&buf[msg_len], &key[0], KEY_LEN);
			msg_len += KEY_LEN;
			memcpy(&buf[msg_len], &iv[0], KEY_LEN);
			msg_len += KEY_LEN;
			write(pipe_fd[1], buf, BUFFER_SIZE_MESSAGE);
			memset(buf, 0, BUFFER_SIZE);
			printf("KEY and IV UPDATE DONE\n");

		// If the server got shutdown message
		} else if (buf[0] == 2) {
			printf("CLIENT INITIATED SYSTEM SHUTDOWN\n");
			printf("=================================\n");
			printf("      SHUTTING DOWN SERVER       \n");
			printf("=================================\n");
			kill(child_pid, SIGKILL);
			break;
		} else {
			printf(" Something Went wrong\n");
			printf(" Got unrecognised input %d\n" ,buf[0]);
			kill(child_pid, SIGKILL);
			break;
		}
	}

	// Close everything 
	close(server_sd);
	SSL_free(ssl);
	SSL_CTX_free(ssl_context);

	return 0;
}

int verify_credentials(char* username, char* password) {

	char found_hash[2*SHA256_DIGEST_LENGTH + 1];
	memset(found_hash, '\0', sizeof(found_hash));

	char file_cred[BUFFER_SIZE];
	memset(file_cred, '\0', sizeof(file_cred));

	char file_user[BUFFER_SIZE_SMALL];
	memset(file_user, '\0', sizeof(file_user));

	char file_pass[2*SHA256_DIGEST_LENGTH + 1];
	memset(file_pass, '\0', sizeof(file_pass));


	FILE* shadow_file = fopen(SHADOW_FILE_PATH, "r");
	int found = 0;
  	// find the user in the database
	while (fgets(file_cred, BUFFER_SIZE, shadow_file) != NULL) {
		// handing new line and extra whitespace characters that could be present
		int length = strlen(file_cred);
		while (length > 0) {
			if (!isspace((unsigned char)file_cred[length - 1])){
				break;
			}
			length--;
			file_cred[length] = '\0';
		}

		// split the credentials
		char* len = strtok(file_cred, SEPARATOR);
		strcpy(file_user, len);
		len = strtok(NULL, SEPARATOR);
		strcpy(file_pass, len);

		// check if the user is in the database
		if (strcmp(username, file_user) == 0) {
			found = 1;
			strcpy(found_hash, file_pass);
			printf("User %s found\n" , username);
			break;
		}
	}
  
  	// check if the user was found
	if (found == 0) {
		printf("User is not present\n");
		fclose(shadow_file);
		exit(1);
	}

	fclose(shadow_file);
  // verify the password
  return password_check(password, found_hash);
}
