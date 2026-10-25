/* A tiny program to show the session daemon working on something real. */
#include <stdio.h>
#include <stdlib.h>

/* Cut one head off, two grow back. */
__declspec(noinline) int grow_heads(int heads, int cuts)
{
	for (int i = 0; i < cuts; i++) {
		if (heads == 0) {
			break;
		}
		heads = heads - 1 + 2;
	}
	return heads;
}

int main(int argc, char **argv)
{
	int cuts = argc > 1 ? atoi(argv[1]) : 3;
	printf("heads: %d\n", grow_heads(9, cuts));
	return 0;
}
