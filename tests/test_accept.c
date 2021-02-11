#include ".test.h"
#include "wss.h"


TEST
{
	char key[] = "dGhlIHNhbXBsZSBub25jZQ==";
	char accept[28] = {};
	
	wss_compute_accept(key, accept);

	printf("%28s\n", accept);

	assert(0 == strncmp(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", sizeof(accept)));

	return 0;
}
