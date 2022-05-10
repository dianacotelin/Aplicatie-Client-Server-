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
int max_number_of_topics = 100;
int max_number_of_subscribers = 50;
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
int find_topic_index (char *topic, int nr_topics, subscriber subscriber) {
    for (int i = 0; i< nr_topics; i++) {
        if (strcmp(subscriber.topics[i].topic, topic) == 0) {
            return i;
        }
    }
    return -1;
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

void create_message(char* buffer, message msg, char ip[], int sock) {
    char topic_name[MSG_LEN];
    int type = buffer[50];

    memset(topic_name, 0, MSG_LEN);
    memcpy(topic_name, buffer, 50);
    strcpy(msg.ip, ip);
    strcpy(msg.topic, topic_name);
    msg.sock = sock;

    if(type == 0) {
        uint32_t num;
        strcpy(msg.data_t, "INT");
        num = (uint32_t)buffer[52] << 24 | (uint32_t)buffer[53] << 16 | (uint32_t)buffer[54] << 8 |
                (uint32_t)buffer[55];
        signed long long int aux = num;
        if (buffer[51] == 1) {
            msg.case_int = -aux;
        } else {
            msg.case_int = aux;
        }
    }

    if (type == 1) {
        uint16_t num = 0;
        strcpy(msg.data_t, "SHORT_REAL");
        num = (uint16_t)buffer[51] << 8 | (uint16_t)buffer[52];
        msg.case_short = num;
    }

    if (type == 2) {
        strcpy(msg.data_t, "FLOAT");
        uint32_t num = 0;
        uint8_t aux = 0;
        num = (uint32_t)buffer[52] << 24 | (uint32_t)buffer[53] << 16 | (uint32_t)buffer[54] << 8 |
                (uint32_t)buffer[55];
        aux = (uint8_t)buffer[56];
        double exp = 1;
        for (int i = 0; i < aux; i++) {
            exp /= 10;
        }
        double aux2 = (double)num * exp;
        if (buffer[51] == 1) {
            msg.case_float = (double) -aux2;
        } else {
            msg.case_float = (double)aux2;
        }
    }
    if (type == 3) {
        strcpy(msg.data_t, "STRING");
        memset(msg.case_string, 0, 1500);
        memcpy(msg.case_string, buffer + 51, 1501);
    }

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

    int sockfd_tcp = socket(PF_INET, SOCK_STREAM, 0);
    DIE(sockfd_tcp < 0, "socket_tcp");

    int sockfd_udp = socket(AF_INET, SOCK_DGRAM, 0);
    DIE(sockfd_udp < 0, "socket_udp");

    int portno = atoi(argv[1]);
    DIE(portno == 0, "atoi");

    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;
    int newsockfd;

    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    
    // Dezactivare alg Naglae
    int flag = 1;
    int res;
    res = setsockopt(sockfd_tcp, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
    DIE(res < 0, "Naglae");

    int ret, n;
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
    char id[ID_LEN];

    char **topics = (char**)malloc(max_number_of_topics * sizeof(char*));
    subscriber *subscribers = calloc(100, sizeof(subscriber));
    for (int i = 0; i < max_number_of_topics; i++) {
        topics[i] = (char*)malloc(50*sizeof(char));
    }

    while(1) {
        tmp_fds = read_fds;
        ret = select(fdmax + 1, &tmp_fds, NULL, NULL, NULL);
        DIE(ret < 0, "select");

        // STDIN data
        if (FD_ISSET(STDIN_FILENO, &tmp_fds)) {
            memset(buffer, 0, BUFLEN);
            fgets(buffer, BUFLEN - 1, stdin);
            // exit command
            if (strncmp(buffer, "exit", 4) == 0) {
                for (int i = 3; i <= fdmax; i++) {
                    if (FD_ISSET(i, &read_fds)) {
                       // close(i);
                    }
                }
                break;
            }
        }

        // UDP CLIENTS
        if (FD_ISSET(sockfd_udp, &tmp_fds)) {
            memset(buffer, 0, BUFLEN);
            clilen = sizeof(cli_addr);
            ret = recvfrom(sockfd_udp, buffer, sizeof(buffer), 0,(struct sockaddr *)&cli_addr, &clilen);
            DIE(ret < 0, "recvfrom");

            
            message msg_udp;
            create_message(buffer, msg_udp, inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));


            message_tcp msg_tcp;
            memset(&msg_tcp, 0, sizeof(message_tcp));
            msg_tcp.client_addr = cli_addr;
            memcpy(&(msg_tcp.topic), &(msg_udp.topic), sizeof(message));

            // Search the topic, and add it if it dosen't exist
            if (! find_topic(topics, msg_tcp.topic)) {
                add_topic(topics, msg_tcp.topic);
            } else {
                // Send messages to the subscribers of this topic
                for (int i = 0; i < subscribers_len; i++) {
                    if (is_subsc (subscribers[i], msg_udp.topic)){
                        if (subscribers[i].client.status == 1) {
                            ret = send(subscribers[i].client.sockfd, &msg_udp, sizeof(msg_udp), 0);
                            DIE(ret < 0, "sendmsg");

                        } else if (subscribers[i].client.status == 0) {
                            for (int j = 0; j < subscribers->nr_topics; j++) {
                                if (strcmp (subscribers[i].topics[j].topic, msg_udp.topic) == 0) {
                                    if (subscribers[i].topics[j].sf == 1) {
                                        message_tcp *copy =(message_tcp *)calloc(1, sizeof(message_tcp));
                                        memcpy(copy, &msg_tcp, sizeof(message_tcp));
                                        queue_enq(subscribers[i].client.messages, copy);
                                    }
                                }
                            }

                        }
                    }
                }
            }


        } else {
            // Client TCP
            for (int i = 0; i<= fdmax; i++) {
                if (FD_ISSET(i, &tmp_fds)) {
                    if (i == sockfd_tcp) {
                        // cerere de conexiune pe socket inactiv (listen)
                        clilen = sizeof(cli_addr);
                        newsockfd = accept(sockfd_tcp, (struct sockaddr *)&cli_addr, &clilen);
                        DIE(newsockfd < 0, "accept");

                        ret = recv (newsockfd, buffer, 10, 0);
                        
                        DIE(ret < 0, "recv");
                        int found = -1;
                        int status = -1;
                        for (int j = 0; j < subscribers_len; j++) {
                            if (! strcmp(buffer, subscribers[j].client.id)) {
                                found = j;
                                status = subscribers[j].client.status;
                                break;
                            }
                        }

                        if ((found == -1) || (subscribers_len = 0)) {
                            // client nou

                            // se adauga un socket nou la multimea descriptorilor de citire
                            FD_SET(newsockfd, &read_fds);
                            if (newsockfd > fdmax) {
                                fdmax = newsockfd;
                            }
                            
                            subscribers_len++;

                            strcpy(subscribers[subscribers_len-1].client.id, buffer);
                            subscribers[subscribers_len -1].client.sockfd = sockfd_tcp;
                            subscribers[subscribers_len -1].client.status = 1;
                            subscribers[subscribers_len -1].nr_topics = 0;
                            subscribers[subscribers_len -1].client.messages = queue_create();
                            printf("New client %s connected from %s:%i.\n", subscribers[subscribers_len-1].client.id, inet_ntoa(cli_addr.sin_addr), cli_addr.sin_port);

                            
                            
                        } else if (status == -1) {
                            // client reconectat
                            FD_SET(newsockfd, &read_fds);
                            subscribers[found].client.sockfd = newsockfd;
                            subscribers[found].client.status = 1;

                            while (!queue_empty(subscribers[found].client.messages)) {
                                message *info = queue_deq(subscribers[found].client.messages);
                                ret = send(subscribers[found].client.sockfd, info, sizeof(char), 0);
                                DIE(ret < 0, "send_messages");
                            }

                        } else if (status == 1) {
                            printf("Client %s already connected.\n", buffer);
                            strcpy(buffer, "quit");
                            ret = send(newsockfd, buffer, sizeof(buffer), 0);
                            DIE(ret < 0, "send");
                        }

                        

                    } else if (i!=STDIN_FILENO) {
                        // s-au primit date pe unul din socketii de client,
                        // asa ca serverul le receptioneaza

                        memset(buffer, 0, BUFLEN);
                        n = recv(i, buffer, sizeof(buffer), 0);
                        DIE(n < 0, "recv");

                        if (n == 0) {
                            int found;

                            for (int j = 0; j < subscribers_len; j++) {
                                if (i == subscribers[j].client.sockfd) {
                                    found = j;
                                }
                            }
                            subscribers[found].client.status = -1;
                            //close(i);
                            FD_CLR(i, &read_fds);
                            printf("Client %s disconnected.\n", subscribers[found].client.id);

                        } else {
                            topic *new_top = (topic *) malloc(sizeof(topic*));
                            if (strncmp(buffer, "subscribe", strlen("subscribe") == 0)) {
                                strncpy(new_top->topic, buffer, strlen(buffer) - 3);
                                char sf[2];
                                sf[0] = buffer[strlen(buffer) - 2];
                                sf[1] = '\0';
                                new_top->sf = atoi(sf);
                                if (find_topic(topics, new_top->topic) == 0) {
                                    add_topic(topics, new_top->topic);
                                }

                                for (int j = 0; j < subscribers_len; j++) {
                                    if (subscribers[j].client.sockfd == i) {
                                        if (is_subsc(subscribers[j], new_top->topic) == 0) {
                                            int aux_nr = subscribers[j].nr_topics;
                                            subscribers[j].nr_topics ++;
                                            strcpy(subscribers[j].topics[aux_nr].topic, new_top->topic);
                                            subscribers[j].topics[aux_nr].sf = new_top->sf;
                                          
                                        }
                                        break;
                                    }
                                }

                            } else if (strncmp(buffer, "unsubscribe", strlen("unsubscribe") == 0)) {
                                for (int j = 0; j < subscribers_len; j++) {
                                    if (subscribers[j].client.sockfd == i) {
                                        if (is_subsc(subscribers[j], new_top->topic) == 0) {
                                            int index = find_topic_index(new_top->topic, subscribers[j].nr_topics, subscribers[j]);
                                            if (index >= 0) {
                                                for (int k = index; k < subscribers[j].nr_topics -1; k++) {
                                                    subscribers[j].topics[k] = subscribers[j].topics[k +1]; 
                                                }
                                                subscribers[j].nr_topics --;
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                            
                        }
                    }


                }
            }
        }
    }
    for (int i = 0; i < subscribers_len; i++) {
        free(subscribers[i].topics);
    }
    free (subscribers);
    for (int i = 0; i < topics_len; i++) {
        free(topics[i]);
    }
    free (topics);
    //close (sockfd_tcp);
    //close (sockfd_udp);



    return 0;
}