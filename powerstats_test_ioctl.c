#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "powerstats.h"

/* This program will simply change the sample_interval to 200 and the 
 * update_interval to 5. */

int main(int argc, char **argv) {
	struct interval interval;
	int file, err;

	file = open("/proc/powerstats", O_RDWR);
	if(file == -1) {
		printf("Opening /proc/powerstats failed\n");
		exit(0);
	}

	interval.sample = 200;
	interval.update = 5;
	err = ioctl(file, PWRS_IOC_SET_INTERVAL, &interval);
	if(err)
		printf("Received error: %d\n", err);

	close(file);
	return 0;
}


