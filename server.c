#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "helpers.h"

int size;
int topics_len;
int subscribers_len;
void usage(char *file)
{
	fprintf(stderr, "Usage: %s server_port\n", file);
	exit(0);
}

void udp_payload (message message_udp, struct sockaddr_in cli_addr, int len) {
    message_tcp msg_tcp;
    memset(&msg_tcp, 0, sizeof(message_tcp));
    msg_tcp.client_addr = cli_addr;
    memcpy(&(msg_tcp.topic), &(message_udp.topic), sizeof(message_udp));
}

int find_topic(char**topics, char*topic) {
    for (int i = 0; i < topics_len; i++) {
        if (strcmp (topics[i], topic) == 0) {
            return 1;
        }
    }
    return 0;
}

void add_topic (char **topics, char *topic) {
    strcpy(topics[topics_len], topic);
    topics_len++;
}

int is_subsc (subscriber subsc, char *topic) {
    for (int i = 0; i< subsc.nr_topics; i++) {
        if (strcmp(subsc.topics[i].topic, topic) == 0) {
            return 1;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, BUFSIZ);

    fd_set read_fds;
    fd_set tmp_fds;
    int fdmax;

    if (argc < 2) {
        usage(argv[0]);
    }

    FD_ZERO(&read_fds);
    FD_ZERO(&tmp_fds);

    int sockfd_tcp = socket(AF_INET, SOCK_STREAM, 0);
    DIE(sockfd_tcp < 0, "socket_tcp");

    int sockfd_udp = socket(AF_INET, SOCK_DGRAM, 0);
    DIE(sockfd_udp < 0, "socket_udp");

    int portno = atoi(argv[1]);
    DIE(portno == 0, "atoi");

    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;
    int clients[MAX_CLIENTS_NO];

    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    
    // Dezactivare alg Naglae
    int flag = 1;
    int res;
    res = setsockopt(sockfd_tcp, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
    DIE(res < 0, "Naglae");

    int ret;
    ret = bind(sockfd_tcp, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr));
    DIE(ret < 0, "bind_tcp");

    ret = bind(sockfd_udp, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr));
    DIE(ret < 0, "bind_udp");

    ret = listen(sockfd_tcp, MAX_CLIENTS);
    DIE(ret < 0, "listen");

    // Se adauga file descriptori
    FD_SET(sockfd_tcp, &read_fds);
    FD_SET(sockfd_udp, &read_fds);
    FD_SET(STDIN_FILENO, &read_fds);

    if (sockfd_tcp > sockfd_udp) {
        fdmax = sockfd_tcp;
    } else {
        fdmax = sockfd_udp;
    }
    char buffer[BUFLEN];

    message message_udp;
    char **topics = (char**)malloc(TOPICS_LEN * sizeof(char*));
    subscriber *subscribers = malloc(MAX_SUBSCRIBERS * sizeof(subscriber));
    for (int i = 0; i < TOPICS_LEN; i++) {
        topics[i] = (char*)malloc(50*sizeof(char));
    }

    while(1) {
        tmp_fds = read_fds;
        ret = select(fdmax + 1, &tmp_fds, NULL, NULL, NULL);
        DIE(ret < 0, "select");

        // STDIN data
        if (FD_ISSET(0, &tmp_fds)) {
            memset(buffer, 0, BUFLEN);
            fgets(buffer, BUFLEN - 1, stdin);
            // exit command
            if (strncmp(buffer, "exit", 4) == 0) {
                for (int i = 0; i <= fdmax; i++) {
                    if (FD_ISSET(i, &read_fds)) {
                        close(i);
                        close(sockfd_tcp);
                        close(sockfd_udp);
                    }
                }
                break;
            }
        }

        // UDP CLIENTS
        if (FD_ISSET(sockfd_udp, &tmp_fds)) {
            memset(&message_udp, 0, sizeof(message_udp));
            clilen = sizeof(cli_addr);

            ret = recvfrom(sockfd_udp, &message_udp, sizeof(message_udp), 0, (struct sockaddr *)&cli_addr, &clilen);
            DIE(ret < 0, "recvfrom");

            message_tcp msg_tcp;
            memset(&msg_tcp, 0, sizeof(message_tcp));
            msg_tcp.client_addr = cli_addr;
            memcpy(&(msg_tcp.topic), &(message_udp.topic), sizeof(message_udp));

            // Search the topic, and add it if it dosen't exist
            if (! find_topic(topics, msg_tcp.topic)) {
                add_topic(topics, msg_tcp.topic);
            } else {
                // Send messages to the subscribers of this topic
                for (int i = 0; i < subscribers_len; i++) {
                    if (is_subsc (subscribers[i], message_udp.topic)){
                        if (subscribers[i].client->status == 1) {
                            ret = send(subscribers[i].client->sockfd, &message_udp, sizeof(message_udp), 0);
                            DIE(ret < 0, "sendmsg");

                        } else if (subscribers[i].client->status == 0) {
                            message_tcp *copy = (message_tcp *)calloc(1, sizeof(message_tcp));
                            memcpy(copy, &msg_tcp, sizeof(message_tcp));
                            queue_enq(subscribers[i].client->messages, copy);

                        }
                    }
                }
            }


        } else {

        }
    }






    return 0;
}