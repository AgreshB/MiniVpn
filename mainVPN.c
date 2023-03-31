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

#include "helper.c"
#include "server.c"
#include "client.c"

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define BUFFER_SIZE_MESSAGE 100
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

#define HMAC_LENGTH 32

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite, plength;

  char buffer[BUFSIZE];
  char buf[BUFSIZE];

  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;

  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  struct sockaddr_in client;
	int clientlen;
  progname = argv[0];

  // Key and IV for encryption/decrpytion
  unsigned char key[KEY_LEN]="abcdefghijklmnop";
  unsigned char iv[KEY_LEN]={0};
  
  // Hashing
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len=0;
  int flag =0;

  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);


  // now need to create a fork for TCP and UDP
  int pipe_fd[2];
	pipe(pipe_fd);
	pid_t pid = fork();


  // Parent process
	if (pid > 0) {
		// Parent process manages the TCP connection
		// Parent process closes up input side
    // because it will only write to the UDP process
		close(pipe_fd[0]);

		int child_pid = pid;
		if (cliserv == SERVER) {
			server_tcp(pipe_fd, child_pid);
		} else if (cliserv == CLIENT) {
			client_tcp(pipe_fd, child_pid, remote_ip);
		}
		exit(0);
	} 
  // Child process
  else if (pid == 0) {
		// Child process manages the UDP connection
		// Child process closes up output side of pipe 
    // because it will only read from Parent TCP process
		close(pipe_fd[1]);

		// Get the key from the TCP process
		// Note that read function will block
		// So the UDP program will wait until it gets the key from the TCP process
		memset(buf, 0, BUFSIZE);
		int ret = read(pipe_fd[0], buf, BUFFER_SIZE_MESSAGE);
		int index = 0;
		if (buf[0] == 1) {
			index++;
			memcpy(&key[0], &buf[index], KEY_LEN);
			index += KEY_LEN;
      memcpy(&iv[0], &buf[index], KEY_LEN);
			index += KEY_LEN;
		} 
    else {
			printf("Something went wrong... Killing both processes on this side\n");
      kill(getppid(), SIGKILL);
			exit(1);
		}

	} else {
		printf("fork() failed!\n");
		exit(1);
	}

  // For UDP socket connection , need SOCK_DGRAM and IPPROTO_UDP
  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("socket()");
    exit(1);
  }

  if(cliserv==CLIENT){
    // fill info for client , regarding  server
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);
    // do not need any connect() for UDP
    net_fd = sock_fd;
    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    
  } else {
    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
      perror("setsockopt()");
      exit(1);
    }
    // fill info for server
    // bind the socket to the port for server
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }
    // UDP doesnt support listen and accept
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);

    net_fd = sock_fd;
    do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
  }
  
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */
      
      nread = cread(tap_fd, buffer, BUFSIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      // write length + packet 
      // need to use sendto , instead of cwrite for UDP
      // before sending packets , need to perform encryption
      do_debug("Starting encryption the packet\n");

      int ret = message_encryption(key,iv,buffer,&nread,1);
      if (ret != 1){
        do_debug("Error in encryption\n");
      }
      else{
        do_debug("Encryption done\n");
      }

      // add HMAC to the packet
      message_HMAC(key , buffer , &nread);

      plength = htons(nread);
      nwrite=sendto(net_fd,(char *)&plength, sizeof(plength),0,(struct sockaddr *)&remote,sizeof(remote));
			nwrite=sendto(net_fd, buffer, nread, 0,(struct sockaddr *)&remote,sizeof(remote));
      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      /* Read length */
      // Have to use recvfrom for UDP      
      nread =recvfrom(net_fd,(char *)&plength, sizeof(plength),0, (struct sockaddr *)&client,&clientlen);
      if(nread == 0) {
        /* ctrl-c at the other end */
        break;
      }
      net2tap++;
      /* read packet */
      // Have to use recvfrom for UDP  
      nread=recvfrom(net_fd,buffer,ntohs(plength),0,(struct sockaddr*)&client, &clientlen);
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      // need to decrypt the packet
      int ret = check_hash(key,buffer,&nread);
      // HMAC return 0 if it matches
      if (ret != 0){
        do_debug("HMAC does not macth\n");
      }
      ret = message_encryption(key,iv,buffer,&nread,0);
      if (ret != 1){
        do_debug("Error in Decryption\n");
      }
      else{
        do_debug("Successful Decrypted Message\n");
      }

      remote=client;
      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer, nread);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
  
  return(0);
}
