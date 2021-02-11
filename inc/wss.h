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

#define SHA1HANDSOFF

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <string.h>


typedef enum
{
	WSS_OPCODE_CONT_FRAME = 0x0,
	WSS_OPCODE_TEXT_FRAME = 0x1,
	WSS_OPCODE_BIN_FRAME  = 0x2,
	WSS_OPCODE_NON_CTRL0  = 0x3,
	WSS_OPCODE_NON_CTRL1  = 0x4,
	WSS_OPCODE_NON_CTRL2  = 0x5,
	WSS_OPCODE_NON_CTRL3  = 0x6,
	WSS_OPCODE_NON_CTRL4  = 0x7,
	WSS_OPCODE_CLOSE_CON  = 0x8,
	WSS_OPCODE_PING       = 0x9,
	WSS_OPCODE_PONG       = 0xA,
	WSS_OPCODE_CTRL0      = 0xB,
	WSS_OPCODE_CTRL1      = 0xC,
	WSS_OPCODE_CTRL2      = 0xD,
	WSS_OPCODE_CTRL3      = 0xF,
} wss_frame_opcode_t;


typedef struct
{
	uint32_t fin         : 1;
	uint32_t rsv         : 3;
	uint32_t opcode      : 4;
	uint32_t mask        : 1;
	uint32_t payload_len : 7;
} wss_frame_hdr_t;


typedef struct
{
	wss_frame_hdr_t hdr;
	union {
		uint16_t len16;
		uint64_t len64;
	} ex_payload_len;
	uint32_t masking_key;
} wss_frame_t;


typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;


void SHA1Transform(uint32_t state[5],const unsigned char buffer[64]);
void SHA1Init(SHA1_CTX * context);
void SHA1Update(SHA1_CTX * context, const unsigned char *data, uint32_t len);
void SHA1Final(unsigned char digest[20], SHA1_CTX * context);
void SHA1(char *hash_out, const char *str, int len);
void base64_encode(void *dst, const void *src, size_t len);


ssize_t wss_read_frame(int sock, void* dst, size_t ex_len)
{
	wss_frame_t frame;
#ifdef WSS_H_TEST
	ssize_t frame_bytes = read(sock, &frame.hdr, sizeof(frame.hdr));
#else
	ssize_t frame_bytes = recv(sock, &frame.hdr, sizeof(frame.hdr), 0);
#endif

	if (frame_bytes != sizeof(frame)) { return -1; /* Something foul happened when reading */ }

	if (frame.hdr.rsv != 0) { return -2; /* non-zero rsv bits should cause a connection failure */}

	// TODO
	switch (frame.hdr.opcode)
	{
		case WSS_OPCODE_CONT_FRAME:
			break;
		case WSS_OPCODE_TEXT_FRAME:
			break;
		case WSS_OPCODE_BIN_FRAME:
			break;
		case WSS_OPCODE_CLOSE_CON:
			break;
		case WSS_OPCODE_PING:
			break;
		case WSS_OPCODE_PONG:
			break;     
		default:
			break;
	}

	if (frame.hdr.payload_len == 126)
	{
#ifdef WSS_H_TEST
		ssize_t pay_len_bytes = read(sock, &frame.ex_payload_len.len16, sizeof(uint16_t));
#else
		ssize_t pay_len_bytes = recv(sock, &frame.ex_payload_len.len16, sizeof(uint16_t), 0);
#endif
		if (pay_len_bytes != sizeof(uint16_t)) { return -3; }
	}
	else if (frame.hdr.payload_len == 127)
	{
#ifdef WSS_H_TEST
		ssize_t pay_len_bytes = read(sock, &frame.ex_payload_len.len64, sizeof(uint64_t));
#else
		ssize_t pay_len_bytes = recv(sock, &frame.ex_payload_len.len64, sizeof(uint64_t), 0);
#endif
		if (pay_len_bytes != sizeof(uint64_t)) { return -3; }
	}

	if (frame.hdr.mask)
	{
#ifdef WSS_H_TEST
		ssize_t mask_bytes = read(sock, &frame.mask, sizeof(uint32_t));
#else
		ssize_t mask_bytes = recv(sock, &frame.mask, sizeof(uint32_t), 0);
#endif
		if (mask_bytes != sizeof(uint32_t)) { return -4; }
	}
}


void wss_compute_accept(char key[24], char accept[28])
{
	char concat[61];
	char sha[21];
	snprintf(concat, sizeof(concat), "%24s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
	SHA1(sha, concat, sizeof(concat)-1);
	base64_encode(accept, sha, 20);
}


int wss_handshake_get_req(
	int sock,
	int (*on_route)(const char* route, void* ctx),
	int (*on_header)(const char* key, const char* value, void* ctx),
	void* cb_ctx)
{
	char buf[1024] = {};

#ifdef WSS_H_TEST
	ssize_t bytes_peeked = read(sock, buf, sizeof(buf));
#else
	ssize_t bytes_peeked = recv(sock, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);
#endif

	if (bytes_peeked == 0) { return -1; /* no data yet */ }
	if (bytes_peeked == -1) { return -2; /* error occured when peeking */ }

	char* line_saveptr;
	char* req_str = buf;
	for (char* line; (line = strtok_r(req_str, "\r\n", &line_saveptr)); req_str = NULL)
	{

		if (req_str)
		{ // for the first line of the "request"
			// every websocket handshake should start with a "GET" verb.
			if (strncmp(line, "GET", 3)) { return -3; /* does not seem to be a websocket */ }

			char *part_saveptr, *http_str = line;
			
			for (char* part; (part = strtok_r(http_str, " ", &part_saveptr)); http_str = NULL)
			{
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

/**
 * 
 * THE FOLLOWWING WAS SHAMELESSLY STOLEN FROM https://github.com/clibs/sha1
 *  
 */

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(
    uint32_t state[5],
    const unsigned char buffer[64]
)
{
    uint32_t a, b, c, d, e;

    typedef union
    {
        unsigned char c[64];
        uint32_t l[16];
    } CHAR64LONG16;

#ifdef SHA1HANDSOFF
    CHAR64LONG16 block[1];      /* use array to appear as a pointer */

    memcpy(block, buffer, 64);
#else
    /* The following had better never be used because it causes the
     * pointer-to-const buffer to be cast into a pointer to non-const.
     * And the result is written through.  I threw a "const" in, hoping
     * this will cause a diagnostic.
     */
    CHAR64LONG16 *block = (const CHAR64LONG16 *) buffer;
#endif
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e, 0);
    R0(e, a, b, c, d, 1);
    R0(d, e, a, b, c, 2);
    R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4);
    R0(a, b, c, d, e, 5);
    R0(e, a, b, c, d, 6);
    R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8);
    R0(b, c, d, e, a, 9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
#ifdef SHA1HANDSOFF
    memset(block, '\0', sizeof(block));
#endif
}


/* SHA1Init - Initialize new context */

void SHA1Init(
    SHA1_CTX * context
)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void SHA1Update(
    SHA1_CTX * context,
    const unsigned char *data,
    uint32_t len
)
{
    uint32_t i;

    uint32_t j;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
        context->count[1]++;
    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;
    if ((j + len) > 63)
    {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64)
        {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else
        i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void SHA1Final(
    unsigned char digest[20],
    SHA1_CTX * context
)
{
    unsigned i;

    unsigned char finalcount[8];

    unsigned char c;

#if 0    /* untested "improvement" by DHR */
    /* Convert context->count to a sequence of bytes
     * in finalcount.  Second element first, but
     * big-endian order within element.
     * But we do it all backwards.
     */
    unsigned char *fcp = &finalcount[8];

    for (i = 0; i < 2; i++)
    {
        uint32_t t = context->count[i];

        int j;

        for (j = 0; j < 4; t >>= 8, j++)
            *--fcp = (unsigned char) t}
#else
    for (i = 0; i < 8; i++)
    {
        finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);      /* Endian independent */
    }
#endif
    c = 0200;
    SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448)
    {
        c = 0000;
        SHA1Update(context, &c, 1);
    }
    SHA1Update(context, finalcount, 8); /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++)
    {
        digest[i] = (unsigned char)
            ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
    /* Wipe variables */
    memset(context, '\0', sizeof(*context));
    memset(&finalcount, '\0', sizeof(finalcount));
}

void SHA1(
    char *hash_out,
    const char *str,
    int len)
{
    SHA1_CTX ctx;
    unsigned int ii;

    SHA1Init(&ctx);
    for (ii=0; ii<len; ii+=1)
        SHA1Update(&ctx, (const unsigned char*)str + ii, 1);
    SHA1Final((unsigned char *)hash_out, &ctx);
    hash_out[20] = '\0';
}

void base64_encode(void *dst, const void *src, size_t len) // thread-safe, re-entrant
{
	static const unsigned char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	assert(dst != src);
	unsigned int *d = (unsigned int *)dst;
	const unsigned char *s = (const unsigned char*)src;
	const unsigned char *end = s + len;
	
	while(s < end)
	{
		uint32_t e = *s++ << 16;
		if (s < end) e |= *s++ << 8;
		if (s < end) e |= *s++;
		*d++ = b64[e >> 18] | (b64[(e >> 12) & 0x3F] << 8) | (b64[(e >> 6) & 0x3F] << 16) | (b64[e & 0x3F] << 24);
	}
	for (size_t i = 0; i < (3 - (len % 3)) % 3; i++) ((char *)d)[-1-i] = '=';
}
#endif
