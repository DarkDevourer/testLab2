obj-m := module_pipe.o

KDIR := /home/george/Kernels/5.10
all:
	$(MAKE) -C $(KDIR) M=$$PWD

check:
	cppcheck --enable=all --inconclusive --library=posix module_pipe.c
	/home/george/Kernels/5.10/scripts/checkpatch.pl -f module_pipe.c

writer:
	gcc -o writer writeproc.c

reader:
	gcc -o reader readproc.c

ioctl:
	rm ioctl
	gcc -o ioctl ioctl.c

load:
	sudo mknod /dev/module_pipe c 248 0
	sudo chmod 777 /dev/module_pipe
	sudo insmod module_pipe.ko

reload:
	sudo rmmod module_pipe
	sudo dmesg -C
	sudo insmod module_pipe.ko