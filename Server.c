#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFFER_SIZE	1000
#define SERVER_PORT	8080
#define QUEUE_SIZE	3

int main(int argc, char *argv[])  {

	int this_sd, other_sd, otherSock_len, noReadBytes;
	struct sockaddr_in thisSockaddr, otherSockaddr;
	char buffer[BUFFER_SIZE];
    char out_buffer[BUFFER_SIZE];
	// Create socket 
	this_sd = socket(PF_INET, SOCK_STREAM, 0);
	if(this_sd == -1)  {
		printf("ERR> Could not create socket, exiting...\n");
		return -1;
	}
	printf("INFO> first client's socket created successfully...\n");

	thisSockaddr.sin_family = AF_INET;
	thisSockaddr.sin_addr.s_addr = INADDR_ANY;
	thisSockaddr.sin_port = htons(SERVER_PORT);

	if( bind(this_sd, (struct sockaddr *)&thisSockaddr, sizeof(thisSockaddr)) < 0)  {
		printf("ERR> Could not bind to socket...\n");
		return -2;
	}
	printf("INFO> bind successful...\n");

	listen(this_sd, QUEUE_SIZE);
	printf("INFO> waiting for client connections...\n");
	
	other_sd = accept(this_sd, (struct sockaddr *)&otherSockaddr, (socklen_t *) &otherSock_len);
	if(other_sd < 0)  {
		printf("ERR> accept failed...\n");
		return -3;
	}
	printf("INFO> connection accepted...\n");
    int cpid= fork();
    while(1){
		if (cpid == 0) //child process
		{
		fgets(out_buffer,sizeof(out_buffer),stdin);
        // Send user's message to server
		if( send(other_sd, out_buffer, strlen(out_buffer)+1, 0) < 0)  {
			printf("ERR> send failed...\n");
			return -2;
		}
		printf("Message sent (%d)bytes...\n",strlen(out_buffer)+1);
		

    }
    else{//parent process
        while( (noReadBytes = recv(other_sd, buffer, BUFFER_SIZE, 0)) > 0 ) {
		printf(">>> received message (%d)bytes : %s\n", noReadBytes, buffer);
		//write(client_sd, buffer, noReadBytes);
	}
	
	if(noReadBytes == 0) {
		printf("INFO> client disconnected...\n");
		return -1;
	}else if (noReadBytes == -1 ) {
		printf("ERR> recv failed...\n");
		return -4;
	}
    }
	}
return 0;
}
	
