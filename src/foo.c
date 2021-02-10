#include "foo.h"

#include <stdio.h>

float
foo (float i, float* j)
{
	float res = i + *j;
	*j = res * 2;

	return res;
}
