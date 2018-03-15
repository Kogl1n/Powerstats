obj-m += powerstats.o
ccflags-y += -std=gnu99 -Wno-parentheses -Wno-missing-braces

all: modules tests

tests:
	gcc -std=gnu99 -o powerstats_test_ioctl powerstats_test_ioctl.c

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f powerstats_test_ioctl

