#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>

#include "module_pipe.h"

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Don't enough parametrs.\n");
		return -1;
	}

	int bytes = atoi(argv[1]);

	int file = open("/dev/module_pipe", O_RDWR);
	if(file == -1) {
		printf("Couldn't open\n");
		return -1;
	}

	printf("Calling ioctl with %d bytes\n", bytes);
	ioctl(file, BUF_CAPACITY, bytes);

	close(file);
	return 0;
}