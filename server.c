#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "helpers.h"

void usage(char *file)
{
	fprintf(stderr, "Usage: %s server_port\n", file);
	exit(0);
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
    while(1) {
        tmp_fds = read_fds;
        ret = select(fdmax + 1, &tmp_fds, NULL, NULL, NULL);
        DIE(ret < 0, "select");

        // Date de la stdin
        if (FD_ISSET(0, &tmp_fds)) {
            memset(buffer, 0, BUFLEN);
            fgets(buffer, BUFLEN - 1, stdin);

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

        // Clienti UDP
        if (FD_ISSET(sockfd_udp, &tmp_fds)) {

        } else {
            
        }
    }






    return 0;
}