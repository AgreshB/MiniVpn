#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28
#define KEY_LEN 16

#define HMAC_LENGTH 32
#define KEY_LEN 16
#define SEPARATOR ":"
#define SEPARATOR_LEN 1

int debug;
char *progname;

// Following function used for message encryption/ decryption
// give it option 0 for decryption and 1 for encryption
int message_encryption(unsigned char *KEY,unsigned char *IV,char *buffer,uint16_t *length,int option)
{
	// local variables
	unsigned char outbuff[BUFSIZE + EVP_MAX_BLOCK_LENGTH];
	unsigned char inbuff[BUFSIZE];
	int output_len =0,tmplen=0;
	int inputlen=*length;
	// copy the buffer to inbuff
	memcpy(inbuff,buffer,inputlen);
	// initialize the cipher context
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	// set the cipher type and mode based in the option
	// option = 1 for encryption
	// option = 0 for decryption
	EVP_CipherInit_ex(&ctx,EVP_aes_128_cbc(),NULL,KEY,IV,option);
	// encrypt/decrypt the message and check for errors
	if(!EVP_CipherUpdate(&ctx,outbuff,&output_len,inbuff,inputlen))
		return 0;
	if(!EVP_CipherFinal_ex(&ctx,outbuff+output_len,&tmplen))
		return 0;

	// update the output length and clean up cipher context
	output_len+=tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	
	// copy final output to buffer 
	memcpy(buffer,outbuff,output_len);
	*length = output_len;

	// retrun 1 for success and 0 for failure
	return 1;
}

// Following function is used for generating the HMAC of the message
void hash_message(unsigned char *KEY,unsigned char *buffer,uint16_t length,char *hash)
{
	HMAC_CTX hmac_context;
	int md_len;
	unsigned char outhash[HMAC_LENGTH];
	memset(outhash, '\0', sizeof(outhash));
	HMAC_CTX_init(&hmac_context);
	HMAC_Init_ex(&hmac_context,KEY,strlen(KEY),EVP_sha256(),NULL);
	HMAC_Update(&hmac_context,buffer,length);
	HMAC_Final(&hmac_context,outhash,&md_len);
	HMAC_CTX_cleanup(&hmac_context);
	memcpy(hash,outhash,HMAC_LENGTH);
}

// Following function is used for appending the HMAC to the message
void message_HMAC(unsigned char *KEY,unsigned char *buffer,uint16_t *length)
{
	char hash[HMAC_LENGTH],inbuff[BUFSIZE];
	int i=0,inputlen=*length;
	memcpy(inbuff,buffer,inputlen);
	hash_message(KEY,inbuff,inputlen,hash);
	for(i=0;i<HMAC_LENGTH;i++)
		*(buffer+inputlen+i) = hash[i];
	inputlen += HMAC_LENGTH;
	*length = inputlen;
}

// Function to check if HMAC is valid
int check_hash(unsigned char *KEY,unsigned char *buffer,uint16_t *length)
{
	char hash1[HMAC_LENGTH],hash2[HMAC_LENGTH],inbuff[BUFSIZE];
	int inputlen = *length,i=0;
	inputlen-=HMAC_LENGTH;
	if(inputlen<=0) return 1;
	
	memcpy(inbuff,buffer,inputlen);
	memcpy(hash1,buffer+inputlen,HMAC_LENGTH);
	hash_message(KEY,buffer,inputlen,hash2);
	*length = inputlen;

	return strncmp(hash1,hash2,HMAC_LENGTH);
}

// check if two password and stored hash match 
int password_check(char *password,char *stored_hash)
{
	// Create conext
	SHA256_CTX hash_context;
	unsigned char calc_hash[SHA256_DIGEST_LENGTH];

	// Hash the password
	SHA256_Init(&hash_context);
	SHA256_Update(&hash_context, password, strlen(password));
	SHA256_Final(calc_hash, &hash_context);

	// Convert the hash to a string
	char calc_hash_string[2*SHA256_DIGEST_LENGTH + 1];
	memset(calc_hash_string, '\0', sizeof(calc_hash_string));
	int i =0;
	for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(calc_hash_string + (i * 2), "%02x", calc_hash[i]);
	}
	calc_hash_string[2*SHA256_DIGEST_LENGTH] = '\0';

	return strcmp(calc_hash_string, stored_hash);
}

// generating a random number
void generate_rand(unsigned char number[], int len) {
	FILE* rand = fopen("/dev/urandom", "r");
	fread(number, sizeof(unsigned char) * len, 1, rand);
	fclose(rand);
}

// generate Key and Iv and store in buffer
int gen_keys(char* buffer, char* key, char* iv, int index) {
  generate_rand(key, KEY_LEN);
	memcpy(&buffer[index], &key[0], KEY_LEN);
	index += KEY_LEN;

	generate_rand(iv, KEY_LEN);
	memcpy(&buffer[index], &iv[0], KEY_LEN);
  index += KEY_LEN;
  return index;
}


