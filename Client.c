#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFFER_SIZE	1000
#define SERVER_PORT	8080

int main(int argc, char *argv[])  {

	int  this_sd, noReadBytes;
	struct sockaddr_in otherSockaddr;
	char in_buffer[BUFFER_SIZE];
	char out_buffer[BUFFER_SIZE];


	// Create socket 
	this_sd = socket(PF_INET, SOCK_STREAM, 0);
	if(this_sd == -1)  {
		printf("ERR> Could not create second client's socket, exiting...\n");
		return -1;
	}
	printf("INFO> socket created successfully...\n");

	otherSockaddr.sin_family = AF_INET;
	otherSockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");//convert string to decimal dotted version
	otherSockaddr.sin_port = htons(SERVER_PORT);

	if( (connect(this_sd, (struct sockaddr *)&otherSockaddr, sizeof(otherSockaddr))) < 0 ) {
		printf("ERR> connection failed...\n");
		return -1;
	}
	printf("INFO> Connection Establishment...\n");
	int cpid= fork();
	while(1)  {
        if(cpid==0){
		fgets(out_buffer,sizeof(out_buffer),stdin);
		// Send user's message to server
		if( send(this_sd, out_buffer, strlen(out_buffer)+1, 0) < 0)  {
			printf("ERR> send failed...\n");
			return -2;
		}
        printf("Message sent (%d)bytes...\n",strlen(out_buffer)+1);
		}
        else{
		// Recieve back a reply from server
		if( (noReadBytes = recv(this_sd, in_buffer, BUFFER_SIZE, 0)) < 0 )  {
			printf("ERR> recv failed...\n");
			return -3;
        }
        printf(">>> received message (%d)bytes : %s\n", noReadBytes, in_buffer);
		}
        }
}
