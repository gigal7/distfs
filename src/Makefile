HEADERS = common.h util.h

all: client server

client: client.c rpc_client.c common.c $(HEADERS)
		gcc -g \
			$(shell pwd)/client.c \
			$(shell pwd)/rpc_client.c \
			$(shell pwd)/common.c \
			-o client -lfuse3

server: server.c rpc_server.c common.c $(HEADERS)
		gcc -g \
			$(shell pwd)/server.c \
			$(shell pwd)/rpc_server.c \
			$(shell pwd)/common.c \
			-o server
clean:
	rm client server

.PHONY: all clean