#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <stdio.h>

#define PORT_NUMBER 2345

using namespace std;
enum TLV_TYPE {
    UNKNOWN = 0,
    GOODBYE = 0x0B1E,
    DATA = 0xDA7A,
    HELLO = 0xE110
};

class Server {
public:
    int listen_client(int port);
    int parser(short* buf, long bytes, char* ip, char* port);
private:
};

int Server::parser(short *buf,long bytes, char* ip, char* port) 
{
	unsigned short 	two_bytes 		= 0;
	unsigned int 	length_field 	= 0;
	unsigned int 	sum_length_field= 0;
	unsigned int 	word_count 		= 0; //1word = 2bytes
	
	for(unsigned int i = 0; i<bytes/2; i=word_count)
	{
		printf("[%s:%s]", ip, port);
		
		if(sum_length_field%2==1)//if LENGTH is odd, this condtion will be true
		{
			// Grep the two_bytes (TYPE) & length_field (LENGTH) in host byte order
			two_bytes 		= ((buf[i+1] & 0xFF) << 8) | 
							  ((buf[i] >> 8) & 0xFF);

			length_field 	= ((buf[i+2] & 0xFF) << 24) 		|
							  (((buf[i+1] >> 8) & 0xFF) << 16) 	|
							  ((buf[i+3] & 0xFF) << 8) 			|
							  ((buf[i+2] >> 8) & 0xFF);
		}
		else
		{
        	// Grep the two_bytes (TYPE) & length_field (LENGTH) in HBO
			two_bytes = buf[i];
			length_field = (buf[i+1] << 16) | buf[i+2];
		}

		// convert both TYPE & LENGTH from HBO to NBO
		two_bytes = htons(two_bytes);
		length_field = htons(length_field);
		
		switch(two_bytes)
		{
			case HELLO:
				printf(" [HELLO] [%d] ", length_field);
				word_count +=3; //6 nibbles = 3 bytes.. because TYPE_SIZE+LENGTH_SIZE
				break;

			case DATA:
				printf(" [DATA] [%d] ", length_field);
				word_count +=3;
				break;

			case GOODBYE:
				printf(" [GOODBYE] [%d] ", length_field);
				word_count +=3;
				break;

			default:
				printf("TYPE UNKNOWN 0x%x\n", two_bytes);
				break;
		} 

		if(two_bytes != HELLO && two_bytes != DATA && two_bytes != GOODBYE)
		{
			printf("Malicious user sending UNKNOWN TYPE data, hence terminating..\n");
			break;
		}

		//print 4 bytes of variable data
		printf(" [");
		
		bool first_byte_printed = false;
		
		if(length_field && sum_length_field % 2 == 1)
		{
			unsigned short temp = htons(buf[word_count++]);
			printf("0x%02x ", (temp & 0xFF));
			first_byte_printed = true;
		}

		unsigned int j;
		for (j=0 ; j<length_field/2 ; j++)
		{
			if(j==2) //For not to print more than 4 bytes
				break;

			unsigned short temp = htons(buf[word_count+j]);
			if(j==0) //This condition will print 2 bytes of data
			{
				printf("0x%02x 0x%02x ", ((temp >> 8) & 0xFF), (temp & 0xFF) );
			}
			else // j==1 - This condition will either print 1 byte or 2 bytes of data depending on first_byte_printed
			{
				first_byte_printed ? printf("0x%02x ", ((temp >> 8) & 0xFF) ) : 
									 printf("0x%02x 0x%02x ", ((temp >> 8) & 0xFF), (temp & 0xFF) );
			}
		}
		
		if(length_field && length_field <= 3 && sum_length_field % 2 == 0)//to handle 
		{
			unsigned short  temp = htons(buf[word_count+j]);
			printf("0x%02x", ((temp >> 8) & 0xFF));
		}

		printf("]\n");

		word_count = word_count + (length_field/2);
	
		sum_length_field += length_field;
	
	}

    return 0;
}


int Server::listen_client(int port) {

    // Create a socket

       int socketDesc = socket(AF_INET, SOCK_STREAM, 0);

       if (socketDesc == -1)

       {

           cerr << "Can't create a socket! Quitting" << endl;

           return -1;

       }

    

       // Bind the ip address and port to a socket

       sockaddr_in hint;

       hint.sin_family = AF_INET;

       hint.sin_port = htons(port); //host to network byte order

       inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);

    

       bind(socketDesc, (sockaddr*)&hint, sizeof(hint));

    

       // Tell Winsock the socket is for listening

       listen(socketDesc, SOMAXCONN);

    

       // Wait for a connection

       sockaddr_in client;

       socklen_t clientSize = sizeof(client);

    

       int clientSocket = accept(socketDesc, (sockaddr*)&client, &clientSize);

    

       char host[NI_MAXHOST];      // Client's remote name

       char service[NI_MAXSERV];   // Service (i.e. port) the client is connect on

    

       memset(host, 0, NI_MAXHOST); // same as memset(host, 0, NI_MAXHOST);

       memset(service, 0, NI_MAXSERV);

    

       if (getnameinfo((sockaddr*)&client, sizeof(client), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0)

       {

           cout << host << " connected on port " << service << endl;

       }

       else

       {

           inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);

           cout << host << " connected on port " << ntohs(client.sin_port) << endl;

       }

    

       // Close listening socket

       close(socketDesc);

    

       // While loop: accept and echo message back to client

       char buf[4096];
	short array[4096];
    

       while (true)

       {

           memset(buf, 0, sizeof(buf));

    

           // Wait for client to send data
		//////  Receive the bytes as byte array, instead of char buffer
//           long bytesReceived = recv(clientSocket, buf, sizeof(buf), 0);

	long bytesReceived = recv(clientSocket, array, sizeof(array), 0);

           if (bytesReceived == -1)

           {

               cerr << "Error in recv(). Quitting" << endl;

               break;

           }

    

           if (bytesReceived == 0)

           {

               cout << "Client disconnected " << endl;

               break;

           }

    
		
//           cout << string(buf, 0, bytesReceived) << endl;

//           parser(buf, host, service);
		parser(array, bytesReceived, host, service);

           

           // Echo message back to client

           send(clientSocket, buf, bytesReceived + 1, 0);

       }

    

    // Close the socket

    close(clientSocket);

    return 0;

}



int main(int argc, const char * argv[]) {

    int port = atoi(argv[1]);

    std::cout << "Hello, TCP!\n";

    Server serv;
    serv.listen_client(port);

    std::cout << "End of program" ;

    return 0;

}
