#ifndef _HELPERS_H
#define _HELPERS_H

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/tcp.h>
/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>
/* ethheader */
#include <net/ethernet.h>
/* ether_header */
#include <arpa/inet.h>
/* icmphdr */
#include <netinet/ip_icmp.h>
/* arphdr */
#include <net/if_arp.h>
#include <asm/byteorder.h>
#include "queue.h"
#include "list.h"

/*
 * Macro de verificare a erorilor
 * Exemplu:
 * 		int fd = open (file_name , O_RDONLY);
 * 		DIE( fd == -1, "open failed");
 */

#define DIE(assertion, call_description)				\
	do {								\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",			\
					__FILE__, __LINE__);		\
			perror(call_description);			\
			exit(EXIT_FAILURE);				\
		}							\
	} while(0)

/* Dimensiunea maxima a calupului de date */
#define BUFLEN 1500
#define MAX_CLIENTS 5
#define ID_LEN 11
#define MSG_LEN 51
#define INFO_LEN 1500
#define MAX_CLIENTS_NO 10
#define TOPICS_LEN 10000
#define MAX_SUBSCRIBERS 1000

typedef struct message {
    int sock;
    char topic[MSG_LEN];
    char ip[16];
    char data_t[20];
    int case_int;
    uint16_t case_short;
    float case_float;
    char case_string[INFO_LEN];
}message;

typedef struct topic {
    char topic[MSG_LEN];
    int sf;
} topic;

typedef struct tcp_client {
    char id[ID_LEN];
    int sockfd;
    int status;
    queue messages;
} tcp_client;

typedef struct subscriber{
    tcp_client *client;
    topic topics[1000];
    int nr_topics;
} subscriber;


typedef struct message_tcp {
    struct sockaddr_in client_addr;
    char topic[MSG_LEN];
    uint8_t data_t;
    char info[INFO_LEN];
} message_tcp;
#endif