/**
 * @file wss.h
 *
 * The example header file for wss
 *
 * All Rights Reserved
 *
 * Author: Kirk Roerig [mr.possoms@gmail.com]
 */

#ifndef __WSS_H__

#include <string.h>

#ifndef WSS_MAX_HDRS
#define WSS_MAX_HDRS 16
#endif

#ifndef WSS_MAX_ROUTE
#define WSS_MAX_ROUTE 256
#endif


typedef struct {
	char key[32], value[256];
} wss_hdr_t;

typedef struct {
	char verb[8], route[WSS_MAX_ROUTE], http_version[16];
	wss_hdr_t headers[16];
} wss_request_t;

int wss_handshake_get_req(
	int sock,
	int (*on_route)(const char* route, void* ctx),
	int (*on_header)(const char* key, const char* value, void* ctx),
	void* cb_ctx)
{
	char buf[1024] = {};

	ssize_t bytes_peeked = recv(sock, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);

	if (bytes_peeked == 0) { return -1; /* no data yet */ }
	if (bytes_peeked == -1) { return -2; /* error occured when peeking */ }

	char* line_saveptr;
	char* req_str = buf;
	for (char* line; !line; req_str = NULL)
	{
		line = strtok_r(req_str, "\r\n", &line_saveptr);

		if (req_str)
		{ // for the first line of the "request"
			// every websocket handshake should start with a "GET" verb.
			if (strncmp(line, "GET", 3)) { return -3; /* does not seem to be a websocket */ }

			char *part_saveptr, *http_str = line;
			
			for (char* part; !part; http_str = NULL)
			{
				part = strtok_r(http_str, " ", &part_saveptr);
				if (part[0] == '/')
				{
					// this seems to be the route part of the http line. Invoke the route
					// callback and let it evaluate if we should continue.
					if (0 != on_route(part, cb_ctx)) { return -4; }
				}

				if (0 == strncmp("HTTP", part, 4))
				{
					// check that HTTP version specified is indeed 1.1
					if (strncmp("HTTP/1.1", part, 8)) { return -5; }
				}
			}

		}
		else
		{ // for every subsequent header line
			char* part_saveptr;
			char* key = strtok_r(line, ": ", &part_saveptr);
			char saved_key[256];

			if (key)
			{
				strncpy(saved_key, key, sizeof(saved_key));
				char* value = strtok_r(NULL, ": ", &part_saveptr);

				// allow the header callback to process this header
				if (0 != on_header(saved_key, value, cb_ctx)) { return -6; }
			}
		}
	}

	return 0;
}


#endif
