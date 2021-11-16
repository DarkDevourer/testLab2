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