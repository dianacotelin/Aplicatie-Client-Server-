#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "helpers.h"

void usage(char *file) {
	fprintf(stderr, "Usage: %s <ID_CLIENT> <IP_SERVER> <PORT_SERVER> \n", file);
	exit(0);
}
void id() {
    fprintf(stderr, "Client ID not valid");
    exit(0);
}
void ip() {
    fprintf(stderr, "Client ID_SERVER not valid");
    exit(0);
}

void errors() {
    fprintf(stderr, "Invalid command");
}

int check_message(char* buffer, char* command) {
    int check = -1;
    buffer[strlen(buffer) - 1] = '\0';
    char *token = strtok(buffer, " ");

    if (token == NULL) {
        errors();
        return -1;
    }
    if (strcmp(token, "subscribe") == 0) {
        strcpy(command, "subscribe");
        check = 0;
    } else if (strcmp(token, "unsubscribe") == 0) {
        strcpy(command, "unsubscribe");
        check = 1;
    } else {
        errors();
        return -1;
    }

    token = strtok(NULL, " ");
    if (token == NULL) {
        errors();
        return -1;
    }
    if (strlen(token) > 50) {
        errors();
        return -1;
    }
    strcat(command, " ");
    strcat(command, token);

    if (check == 0) {
        token = strtok(NULL, " ");
        if (token == NULL) {
            errors();
            return -1;
        }
        if (token[0] != '0' && token[0] != '1') {
            errors();
            return -1;
        }

        strcat(command, " ");
        strcat(command, token);
    }
    return check;
    
}
int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, BUFSIZ);

    int sockfd, ret, fd_max;
    struct sockaddr_in serv_addr;
    char buffer[BUFLEN];
    fd_set read_fds, tmp_fds;

    if (argc < 4) {
        usage(argv[0]);
    }

    if (strlen(argv[1]) > ID_LEN) {
        id();
    }

    if (strlen(argv[2]) > 15) {
        ip();
    }


    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    DIE(sockfd < 0, "socket_tcp");
    // Dezactivare alg Naglae
    int flag = 1;
    int res;
    res = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
    DIE(res < 0, "Naglae");


    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[3]));
    ret = inet_aton(argv[2], &serv_addr.sin_addr);
    DIE(ret == 0, "inet_aton");

    
    FD_ZERO(&read_fds);
    FD_ZERO(&tmp_fds);

    ret = connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
    DIE(ret < 0, "connect");

    FD_SET(STDIN_FILENO, &read_fds);
    FD_SET(sockfd, &read_fds);

    fd_max = sockfd;
    //printf("%s", id);
    ret = send(sockfd, argv[1], 10, 0);
    DIE (ret < 0, "send");
    
    ret = recv(sockfd, buffer, BUFLEN, 0);
    DIE (ret < 0, "recv");

    if (strncmp (buffer, "quit", strlen("quit")) == 0) {
        close(sockfd);
        return 0;
    }

    char messageS[BUFLEN];

    while (1) {
        tmp_fds = read_fds;

        ret = select(sockfd + 1, &tmp_fds, NULL, NULL, NULL);
        DIE(ret < 0, "select");
        if (FD_ISSET(STDIN_FILENO, &tmp_fds)) {
            memset(buffer, 0, BUFLEN);
            fgets(buffer, BUFLEN - 1, stdin);

            if (strncmp(buffer, "exit", 4) == 0) {
                break;
            }

            int checkk = check_message(buffer, messageS);

            if (checkk >= 0) {
                ret = send(sockfd, &messageS, sizeof(messageS), 0);
                DIE(ret < 0, "send");
                if (checkk == 0) {
                    printf("Subscribed to topic.\n");
                    fflush(stdout);
                } else {
                    printf("Unsubscribed from topic.\n");
                    fflush(stdout);
                }
            }
        }
        if (FD_ISSET(sockfd, &tmp_fds)) {
            // Date de la server
            message message_udp;
            ret = recv(sockfd, &message_udp, sizeof(message), 0);
            DIE(ret < 0, "receive");
            printf("%s:%d -%s - ", message_udp.ip, message_udp.sock, message_udp.topic);
            if (strcmp(message_udp.data_t, "INT") == 0) {
                printf("INT - %d\n", message_udp.case_int);
            }
            if (strcmp(message_udp.data_t, "FLOAT") == 0) {
                printf("FLOAT - %lf\n", message_udp.case_float);
            }
            if (strcmp(message_udp.data_t, "SHORT_REAL") == 0) {
                printf("SHORT_REAL - %f\n", (double)message_udp.case_short);
            }
            if (strcmp(message_udp.data_t, "STRING") == 0) {
                printf("STRING - %s\n", message_udp.case_string);
            }

        }
    }

    close(sockfd);

    return 0;
}