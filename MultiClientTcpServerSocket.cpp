#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <stdio.h>

using namespace std;

enum TLV_TYPE
{
    GOODBYE = 0x0B1E,
    DATA = 0xDA7A,
    HELLO = 0xE110
};

struct ClientSockInfo
{
	int sd;
	char hostname[NI_MAXHOST];
	char port[NI_MAXSERV];
};

class Server 
{
public:
    // Public functions
	Server(int port);
    void ServiceClients(void);
	
private:
	// Private functions
	ClientSockInfo* GetClientSockInfo(int client_sd);
	int Parser(short* buf, long bytes, char* ip, char* port);
	
	
	
	// Private variables
	int mServListeningSD; 	//Server Listening socket desc
	fd_set mAllSD; 			//All socket descriptor including the listening socket
	ClientSockInfo mClients[4];  //Client info
	int mClientCounter;
};


Server::Server(int port)
{
	mServListeningSD = -1;
	FD_ZERO(&mAllSD);
	memset(mClients, 0, sizeof(mClients));
	mClientCounter = 0;
	
	//1. Create a socket
	mServListeningSD = socket(AF_INET, SOCK_STREAM, 0);

	//2. Bind the ip address and port to a socket
	if (mServListeningSD != -1)
	{
		sockaddr_in hint;
		hint.sin_family = AF_INET;
		hint.sin_port = htons(port); //host to network byte order
		inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);

		bind(mServListeningSD, (sockaddr*)&hint, sizeof(hint));

		//3. Listen
		listen(mServListeningSD, SOMAXCONN);
		
		FD_SET(mServListeningSD, &mAllSD);
	}
}

ClientSockInfo* Server::GetClientSockInfo(int client_sd)
{
	
	ClientSockInfo* sInfo = NULL;
	for(int i = 0; i < mClientCounter; i++)
	{
		if(mClients[i].sd == client_sd)
		{
			sInfo = &mClients[i];
			break;
		}
	}
	return sInfo;
}

int Server::Parser(short *buf,long bytes, char* ip, char* port) 
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

		//print upto 4 bytes of data bytes
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
		
		(first_byte_printed && length_field % 2 == 0) /*Odd length followed by even length*/ ? word_count = word_count + ((length_field/2) - 1) : word_count = word_count + (length_field/2);
		sum_length_field += length_field;
	
	}

    return 0;
}

void Server::ServiceClients(void)
{
	while(true)
	{
		fd_set copy_allSD = mAllSD;
		
		int socketCount = select(0, &copy_allSD, nullptr, nullptr, nullptr);
		
		for(int i=0; i < socketCount; i++)
		{
			int sock = copy_allSD.fd_array[i];
			
			if(sock == mServListeningSD)
			{
				sockaddr_in client;
				socklen_t clientSize = sizeof(client);

				//Accept new connection
				int client_sock = accept(mServListeningSD, (sockaddr*)&client, &clientSize);
				
				if(mClientCounter >= 3)
				{
					printf("Cannot accept new clients, maximum clients is 4\n");
					close(client_sock);
				}
				
				//Add the new connection to the list of connected clients
				FD_SET(client_sock, &mAllSD);
				
				char host[NI_MAXHOST];      // Client's remote name
				char service[NI_MAXSERV];   // Service (i.e. port) the client is connect on

				memset(host, 0, NI_MAXHOST); // same as memset(host, 0, NI_MAXHOST);
				memset(service, 0, NI_MAXSERV);

				if (getnameinfo((sockaddr*)&client, sizeof(client), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0)
				{
					printf("%s connected on port %s\n", host, service);
				}
				mClients[mClientCounter].sd 		= client_sock;
				//mClients[mClientCounter].hostname 	= host;
				strcpy(mClients[mClientCounter].hostname, host);
				//mClients[mClientCounter].port 	= service;
				strcpy(mClients[mClientCounter].port, service);
				mClientCounter++;
			}
			else
			{
				//Accept a new message from the existing client socket
				//accept and echo message back to client
				char buf[4096];
				short array[4096];
				
				memset(buf, 0, sizeof(buf));
				long bytesReceived = recv(sock, array, sizeof(array), 0);

				if(bytesReceived <=0)
				{
					if (bytesReceived == -1)
					{
						printf("Error in recv(). Quitting\n");
					}

					if (bytesReceived == 0)
					{
						printf("Client disconnected\n");
					}
					mClientCounter--;
					ClientSockInfo* clientSockInfo = GetClientSockInfo(sock);
					if(clientSockInfo)
					{
						memset(clientSockInfo, 0, sizeof(ClientSockInfo));
					}
					close(sock);
					FD_CLR(sock, &mAllSD);
				}
				else //received data from client
				{
					ClientSockInfo* clientSockInfo = GetClientSockInfo(sock);
					
					if(clientSockInfo)
					{
						Parser(array, bytesReceived, clientSockInfo->hostname, clientSockInfo->port);
          			
						// Echo message back to client
						send(sock, buf, bytesReceived + 1, 0);
					}
				}
			}
		}
	}
}


int main(int argc, const char * argv[]) 
{
	int port = 2345;//atoi(argv[1]);
    std::cout << "Hello, TCP!\n";


    Server serv(port);
    
	serv.ServiceClients();

    std::cout << "End of program" ;

    return 0;
}
