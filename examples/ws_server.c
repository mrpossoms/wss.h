#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdlib.h>

#include "wss.h"

char ACCEPT_KEY[29];

int on_route(const char* route, void* ctx)
{
	fprintf(stderr, "Request for '%s'\n", route);
	return 0;
}

int on_header(const char* key, const char* value, void* ctx)
{
	fprintf(stderr, "[HDR] %s => %s\n", key, value);

	if (0 == strncmp("Sec-WebSocket-Key", key, 17))
	{
		wss_compute_accept(value, ACCEPT_KEY);
		fprintf(stderr, "computed accept key %s\n", ACCEPT_KEY);
	}

	return 0;
}

int main (int argc, const char* argv[])
{
	int listen_socket = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in name = {};
	name.sin_family      = AF_INET;
	name.sin_port        = htons(atoi(argv[1]));
	name.sin_addr.s_addr = htonl(INADDR_ANY);

	if (listen_socket < 0)
	{
		fprintf(stderr, "listen sock creation failed");
		return -1;
	}

	// allow port reuse for quicker restarting
#ifdef __linux__
	int use = 1;
	if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEPORT, (char*)&use, sizeof(use)))
	{
		close(listen_socket);
		fprintf(stderr, "Setting SO_REUSEPORT to listen socket failed");
		return -2;
	}
#endif

	// bind the listening sock to port number
	if (bind(listen_socket, (const struct sockaddr*)&name, sizeof(name)))
	{
		close(listen_socket);
		fprintf(stderr, "listen sock bind failed");
		return -3;
	}

	// begin listening
	if(listen(listen_socket, 1))
	{
		close(listen_socket);
		fprintf(stderr, "listen sock listen failed");
		return -4;
	}

	struct sockaddr_in client_name = {};
	socklen_t client_name_len = 0;
	int client_sock = accept(listen_socket, (struct sockaddr*)&client_name, &client_name_len);

	usleep(1000);
	int res = wss_handshake_get_req(client_sock, on_route, on_header, NULL);
	assert(res == 0);

	wss_handshake_respond(client_sock, 0, NULL, ACCEPT_KEY);

	while(1)
	{
		char buf[1024] = {};
		wss_frame_t frame = {};
		ssize_t bytes = wss_read_frame(client_sock, &frame, buf, sizeof(buf));

		if (bytes < 0)
		{
			fprintf(stderr, "READ ERROR\n");
			return -1;
		}
		write(STDERR_FILENO, buf, bytes);

		frame.hdr.mask = 0;
		char echo_buf[1024] = {};
		int echo_len = snprintf(echo_buf, sizeof(echo_buf), "echo: %s\n", buf);
		wss_write_frame(client_sock, frame.hdr, echo_buf, echo_len);
	}

	return 0;
}