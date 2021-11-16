#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

int main()
{
	int reader = open("/dev/module_pipe", O_RDONLY);
	if (reader == -1)
	{
		printf("Failed to open.\n");
		return -1;
	}
	printf("Success.\n");

	char buf[50];

	int read_bytes = read(reader, buf, 21);
	printf("Successfully read %d bytes.\n", read_bytes);

	printf("%s",buf);

	close(reader);
	printf("Closed file.\n");
	return 0;
}