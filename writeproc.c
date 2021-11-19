#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		printf("There is not enought info about string.\n");
		return -1;
	}

	int writer = open("/dev/module_pipe", O_WRONLY);
	if (writer == -1)
	{
		printf("Failed to open.\n");
		return -1;
	}
	printf("Success.\n");

	int bytes = atoi(argv[2]);

	char *str;
	str = malloc(bytes);

	memcpy(str, argv[1], bytes);
	write(writer, str, bytes);
	printf("Successfully wrote %d bytes.", bytes);
	free(str);

	close(writer);
	printf("Closed file.\n");
	return 0;
}