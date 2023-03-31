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
#define BUFFER_SIZE_SMALL 50   


// packet related constants
#define PORT 55555
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28


// Encryption / SSL related constants
#define CACERT "ca.crt"
#define HMAC_LENGTH 32
#define KEY_LEN 16
#define SEPARATOR ":"
#define SEPARATOR_LEN 1


int client_tcp(int pipe_fd[], int child_pid, char* server_ip) {
	// sockets and ssl stuff
	int err ,cli_sd;
	struct sockaddr_in cli_hints;
	SSL_CTX* ssl_context;
	SSL* ssl;
	SSL_METHOD *ssl_m;

	// buffer for everything
	char buf[BUFFER_SIZE];
	char* cmd[BUFFER_SIZE_SMALL];
	unsigned char key[KEY_LEN];
	unsigned char iv[KEY_LEN];
	int index = 0;

  do_debug("Checking certificate for client !!\n");   

	SSLeay_add_ssl_algorithms();
	ssl_m = SSLv23_client_method();
	SSL_load_error_strings();
	ssl_context = SSL_CTX_new(ssl_m);
	if (ssl_context == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ssl_context, CACERT, NULL);

  do_debug("certificate for client checked\n");

	
	// TCP socket creation and connect to server
	cli_sd = socket(AF_INET, SOCK_STREAM, 0);
	if(cli_sd < 0){
		perror("socket");
		exit(1);
	}

	memset(&cli_hints, '\0', sizeof(cli_hints));
	cli_hints.sin_family = AF_INET;
	cli_hints.sin_addr.s_addr = inet_addr(server_ip);
	cli_hints.sin_port = htons(PORT);
	err = connect(cli_sd, (struct sockaddr*) &cli_hints, sizeof(cli_hints));
	if(err < 0){
		perror("connect");
		exit(1);
	}


	
	// initialize SSL connection

	ssl = SSL_new(ssl_context);
	if(ssl == NULL){
		ERR_print_errors_fp(stderr);
		exit(2);
	}
	SSL_set_fd(ssl, cli_sd);
	if(SSL_connect(ssl) == -1){
		ERR_print_errors_fp(stderr); 
		exit(2);
	}
	
	/* Verify server certificate */
	int common_name_verified = verify_server(ssl);

	if (common_name_verified == 0) {
		printf("Server common name cannot be verified\n");
		// kill the parent and the child processes
		buf[0] = 0;
		buf[1] = 0;
		if (SSL_write(ssl, buf, 2) <= 0) {
			printf("Error writing to SSL socket. \n");
		}
		kill(child_pid, SIGKILL);
		exit(1);
	}

	// Once server name verified , need to create Key and IV and
	// verify user credentials
	// Generate a secret key for the UDP tunnel encryption
	index = gen_keys(buf, key, iv, 0);
	//get username and password
	int total = get_user_data(buf , index);

	// send for authentication
	if (SSL_write(ssl, buf, total) <= 0) {
		printf("Error writing to SSL socket. \n");
		kill(child_pid, SIGKILL);
		exit(1);
	}
	memset(buf, 0, BUFFER_SIZE);
	// Receieve response of authentication
	if( SSL_read(ssl, buf, sizeof(buf) - 1) <= 0) {
		printf("Error reading from SSL socket. \n");
		kill(child_pid, SIGKILL);
		exit(1);
	}
	// If the authentication is successful
	if (buf[0] == 0) {
		if (buf[1] != 1){
			printf("Wrong username or password. \n");
			kill(child_pid, SIGKILL);
			exit(1);
		}
		printf("Authentication successful. \n");
	} 
	memset(buf, 0, BUFFER_SIZE);


	// Send the key to the pipe (UDP process)
	index = 0;
	buf[0] = 1;
	index++;
	memcpy(&buf[index], &key[0], KEY_LEN);
	index += KEY_LEN;
	memcpy(&buf[index], &iv[0], KEY_LEN);
	index += KEY_LEN;
	write(pipe_fd[1], buf, BUFFER_SIZE_MESSAGE);

	// Go to infinite loop to listen to the user control commands and send them to the server
	sleep(1);
	while (2==2) {
		printf("Enter command: ");
		scanf("%99s", cmd);
		// BONUS SECTION 
		// Perform KEY and IV UPDATE
		if (strcmp(cmd, "1") == 0) {
			printf("Updating KEY and IV\n");
			// Generate new random key and IV
			memset(buf, 0, BUFFER_SIZE);
      		buf[0] = 1; 
			index = gen_keys(buf, key, iv, 1);
			if (SSL_write(ssl, buf, BUFFER_SIZE_MESSAGE) <= 0) {
				printf("Error writing to SSL socket. \n");
				kill(child_pid, SIGKILL);
				exit(1);
			}
			// Send the new key to the pipe (to the UDP program)
			buf[0] = 1;
			index = 1;
			memcpy(&buf[index], &key[0], KEY_LEN);
			index += KEY_LEN;
			memcpy(&buf[index], &iv[0], KEY_LEN);
			index += KEY_LEN;
			write(pipe_fd[1], buf, BUFFER_SIZE_MESSAGE);
			printf("KEY and IV updated complete\n");
		
		} 
		// If it is a shutdown command
		else if (strcmp(cmd, "2") == 0) {
			printf("SYSTEM SHUTDOWN INITIATED\n");
			printf("=================================\n");
			printf("      SHUTTING DOWN CLIENT       \n");
			printf("=================================\n");
			buf[0] = 2;
			if( SSL_write(ssl, buf, BUFFER_SIZE_MESSAGE) <= 0) {
				printf("Error writing to SSL socket. \n");
				kill(child_pid, SIGKILL);
				exit(1);
			}
			kill(child_pid, SIGKILL);
			break;
		} else {
			printf("Only following options allowed: \n1: Key & IV updation \n2: System Shutdown \n");
		}

	}
	// Close everything
	SSL_shutdown(ssl);
	close(cli_sd);
	SSL_free(ssl);
	SSL_CTX_free(ssl_context);

	return 0;
}


int get_user_data(char* buf, int point) {
  	// initialize variables
	char username[BUFFER_SIZE_SMALL];
	// Get user name
	printf("Please Enter Username: ");
	scanf("%s", username);
	// Get password , using termois.h getpass function
	char* password = (char *) getpass("Enter Password: ");
	// strcpy(password, pass);
	username[strlen(username)] = '\0';
	password[strlen(password)] = '\0';
	// Combined with format <username>:<password>
	memcpy(&buf[point], &username[0], strlen(username));
	point += strlen(username);
	// seperator is ":"
	memcpy(&buf[point], &SEPARATOR[0], SEPARATOR_LEN);
	point += SEPARATOR_LEN;
	memcpy(&buf[point], &password[0], strlen(password));
	point += strlen(password);

	return point;
}


// function to verify the server certificate
int verify_server(SSL* ssl) {
	// Get server's certificate
	X509* sc = SSL_get_peer_certificate(ssl);
	if (sc == NULL) {
		printf("Error getting server certificate. \n");
		return 0;
	}
	// Get the server common name from the certificate
	char check[2*BUFFER_SIZE_SMALL];
	X509_NAME *server = X509_get_subject_name(sc);
	int res = X509_NAME_get_text_by_NID(server, NID_commonName, check, 100);
	// if process went through , then the server certificate is valid
	return 1;
}