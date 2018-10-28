run : client server
	xterm ./client &
	xterm ./server &

server : recvRawEth.c
	gcc recvRawEth.c -o server

client : sendRawEth.c
	gcc sendRawEth.c -o client
