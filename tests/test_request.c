#include ".test.h"
#include "wss.h"


const char REQ[] =
"GET /chat HTTP/1.1\r\n"
"Host: example.com:80\r\n"
"Upgrade: websocket\r\n"
"Connection: Upgrade\r\n"
"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
"\r\n";

int GOT_ROUTE = 0;
int GOT_HOST = 0;
int GOT_UPGRADE = 0;
int GOT_CONNECTION = 0;
int GOT_SEC_WEBSOCKET_KEY = 0;

int on_route(const char* route, void* ctx)
{
	if (0 == strncmp("/chat", route, 5)) { GOT_ROUTE = 1; }
	return 0;
}

int on_header(const char* key, const char* value, void* ctx)
{
	if (0 == strncmp("Host", key, 4) && 0 == strncmp("example.com", value, 14)) { GOT_HOST = 1; } // TODO: fix this, port should be included
	if (0 == strncmp("Upgrade", key, 7) && 0 == strncmp("websocket", value, 9)) { GOT_UPGRADE = 1; }
	if (0 == strncmp("Connection", key, 10) && 0 == strncmp("Upgrade", value, 7)) { GOT_CONNECTION = 1; }
	if (0 == strncmp("Sec-WebSocket-Key", key, 17) && 0 == strncmp("dGhlIHNhbXBsZSBub25jZQ==", value, 24)) { GOT_SEC_WEBSOCKET_KEY = 1; }

	return 0;
}

TEST
{
	int pipe_fd[2];
	pipe(pipe_fd);

	write(pipe_fd[1], REQ, sizeof(REQ));

	wss_handshake_get_req(pipe_fd[0], on_route, on_header, NULL);

	assert(GOT_ROUTE);
	assert(GOT_HOST);
	assert(GOT_UPGRADE);
	assert(GOT_CONNECTION);
	assert(GOT_SEC_WEBSOCKET_KEY);
	
	return 0;
}
