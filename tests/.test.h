#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <math.h>

void*
my_get_file_buffer (const char* path, size_t* buf_size, uint64_t* ckhsum)
{
	static void* mapped_file_buf;
	static size_t last_size;

	if (mapped_file_buf)
	{
		munmap (mapped_file_buf, last_size);
		mapped_file_buf = NULL;
	}

	if (NULL == path)
	{
	return NULL;
	}
	if (NULL == buf_size)
	{
	return NULL;
	}
	if (NULL == ckhsum)
	{
	return NULL;
	}

	// open the file
	int fd = open (path, O_RDONLY);
	if (fd < 0)
	{
		return NULL;
	}

	// get the size
	*buf_size = lseek (fd, 0, SEEK_END);
	lseek (fd, 0, SEEK_SET);
	last_size = *buf_size;

	// map the file
	mapped_file_buf = mmap (NULL, last_size, PROT_READ, MAP_PRIVATE, fd, 0);

	return mapped_file_buf;
}


#define TEST int main (int argc, const char* argv[])
