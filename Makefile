CFLAGS = -Wall -g
CC = gcc

# Portul pe care asculta serverul
PORT_SERVER = 8080

# Adresa IP a serverului
IP_SERVER = 127.0.0.1

ID_CLIENT = diana

all: server subscriber 

# Compileaza server.c
server: server.c queue.c list.c

# Compileaza subscriber.c
subscriber: subscriber.c queue.c list.c

.PHONY: clean run_server run_subscriber

# Ruleaza serverul
run_server:
	./server ${PORT}

# Ruleaza subscriberul 	
run_subscriber:
	./subscriber ${ID_CLIENT} ${IP_SERVER} ${PORT_SERVER}

clean:
	rm -f server subscriber
