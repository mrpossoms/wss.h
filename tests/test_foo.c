#include ".test.h"
#include "foo.h"

/**
 * A test is nothing more than a stripped down C program
 * returning 0 is success. Use asserts to check for errors
 */
TEST
{
	float j = 1;
	assert (foo (1, &j) == 2);
	assert (j == 4);
	return 0;
}
