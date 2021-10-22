/*
 * compile the program with g++ server.cpp in linux terminal, it generates a.out
 * run the program with ./a.out 2345
 * 2345 is the listening port number.
 *
 * Once this server program is run, it goes to listening mode. Now open another terminal and run netcat command
 * echo 'E11000000000da7a000000091112131415161718190b1e00000000' | xxd -r -p | nc -N -p 5625 localhost 2345
 *
 * Server program will parse the hex input received on the listening port, and parses TLV data, decode and prints output.
 * Another to test the server is run a telnet client which sends character input
 * telnet localhost 2345
 *
 * This time, the characters entered from telnet is not recognized and prints Unkwown/Undefined type for any type other than 0xE110, 0xDa7a, 0xB1E
 *
 */


#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <stdio.h>

using namespace std;

enum TLV_TYPE
{
    UNKNOWN = 0,
    GOODBYE = 0x0B1E,
    DATA = 0xDA7A,
    HELLO = 0xE110
};

class Server
{
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
			two_bytes 	= ((buf[i+1] & 0xFF) << 8) |
					  ((buf[i] >> 8) & 0xFF);

			length_field 	= ((buf[i+2] & 0xFF) << 24) 		|
					  (((buf[i+1] >> 8) & 0xFF) << 16) 	|
					  ((buf[i+3] & 0xFF) << 8) 		|
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
				printf(" TYPE UNKNOWN 0x%x\n", two_bytes);
				break;
		}

		if(two_bytes != HELLO && two_bytes != DATA && two_bytes != GOODBYE)
		{
			printf("Malicious user sending UNKNOWN TYPE data, hence terminating..\n");
			break;
		}

		//print upto 4 bytes of data bytes
		printf(" [");

		unsigned int print_data_byte_count = 0;
		bool first_byte_printed = false;
		if(length_field && sum_length_field % 2 == 1)
		{
			unsigned short temp = htons(buf[word_count++]);
			printf("0x%02x ", (temp & 0xFF));
			first_byte_printed = true;
			print_data_byte_count++;
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
				print_data_byte_count += 2;
			}
			else // j==1 - This condition will either print 1 byte or 2 bytes of data depending on first_byte_printed
			{
				if(first_byte_printed)
				{
					printf("0x%02x ", ((temp >> 8) & 0xFF) );
					print_data_byte_count++;
				}
				else
				{
					printf("0x%02x 0x%02x ", ((temp >> 8) & 0xFF), (temp & 0xFF) );
					print_data_byte_count += 2;
				}
			}
		}

		if(length_field && length_field <= 3 && sum_length_field % 2 == 0 && 
		   print_data_byte_count <=3 && print_data_byte_count < length_field) 
		{
			unsigned short  temp = htons(buf[word_count+j]);
			printf("0x%02x", ((temp >> 8) & 0xFF));
		}

		printf("]\n");
		
		word_count = (first_byte_printed && (length_field % 2 == 0)) ? 
					word_count + ((length_field/2) - 1) :  	/*for odd length followed by even length*/
					word_count + (length_field/2);		/*for odd-odd,even-odd,even-even*/
		sum_length_field += length_field;
	}

    return 0;
}


int Server::listen_client(int port) 
{
	//1. Create a socket
	int socketDesc = socket(AF_INET, SOCK_STREAM, 0);

	if (socketDesc == -1)
	{
		printf("Can't create a socket! Quitting \n");
		return -1;
	}

	//2. Bind the ip address and port to a socket
	sockaddr_in hint;
	hint.sin_family = AF_INET;
	hint.sin_port = htons(port); //host to network byte order
	inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);

	bind(socketDesc, (sockaddr*)&hint, sizeof(hint));

	//3. Listen
	listen(socketDesc, SOMAXCONN);

	//4. Wait for a connection
	sockaddr_in client;
	socklen_t clientSize = sizeof(client);

	int clientSocket = accept(socketDesc, (sockaddr*)&client, &clientSize);

	char host[NI_MAXHOST];      // Client's remote name
	char service[NI_MAXSERV];   // Service (i.e. port) the client is connect on

	memset(host, 0, NI_MAXHOST); // same as memset(host, 0, NI_MAXHOST);
	memset(service, 0, NI_MAXSERV);

	if (getnameinfo((sockaddr*)&client, sizeof(client), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0)
	{
		printf("%s connected on port number %s\n", host, service);
	}
    	else
	{
		inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
		printf("%s connected on port %d\n", host, ntohs(client.sin_port));
	}

	// Close listening socket
	close(socketDesc);

	// While loop: accept and echo message back to client
	char buf[4096];
	short array[4096];

	while (true)
	{
		memset(buf, 0, sizeof(buf));
		long bytesReceived = recv(clientSocket, array, sizeof(array), 0);

		if (bytesReceived == -1)
		{
			printf("Error in recv(). Quitting\n");
			break;
		}

		if (bytesReceived == 0)
		{
			printf("Client disconnected\n");
			break;
		}

		parser(array, bytesReceived, host, service);

        // Echo message back to client
        send(clientSocket, buf, bytesReceived + 1, 0);
	}

    // Close the socket
    close(clientSocket);

    return 0;
}



int main(int argc, const char * argv[])
{
    int port = 2345;

    if(argc > 1)
    {
	port = atoi(argv[1]);
    }
    else
    {
	printf("Enter port number as command line input\n> ./a.out 2345\n");
	return 0;
    }


    std::cout << "Hello, TCP!\n";

    Server serv;
    serv.listen_client(port);

    std::cout << "End of program" ;

    return 0;
}
