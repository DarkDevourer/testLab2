#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

int main()
{
	int writer = open("/dev/module_pipe", O_WRONLY);
	if (writer == -1)
	{
		printf("Failed to open.\n");
		return -1;
	}
	printf("Success.\n");

	char *str = "Szeth-son-son-Vallano, Truthless of Shinovar, wore white on the day he was to kill a king.";
	int written_bytes = write(writer, str, 44);
	printf("Successfully wrote %d bytes.\n", written_bytes);

	close(writer);
	printf("Closed file.\n");
	return 0;
}