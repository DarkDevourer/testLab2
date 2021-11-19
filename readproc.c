#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("There is not enought info about string.\n");
		return -1;
	}

	int reader = open("/dev/module_pipe", O_RDONLY);
	if (reader == -1)
	{
		printf("Failed to open.\n");
		return -1;
	}
	printf("Success.\n");

	int bytes = atoi(argv[1]);
	char *str;
	str = malloc(bytes);

	int read_bytes = read(reader, str, bytes);
	printf("Successfully read %d bytes.\n", read_bytes);

	printf("%s\n",str);
	free(str);

	close(reader);
	printf("Closed file.\n");
	return 0;
}