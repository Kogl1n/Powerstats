/*
 * circmod.h 
 * 
 * Author: Bjoern Broemstrup, Alexander Koglin
 * 
 * This file is part of the course material „Kernel Programming“ 
 * Praktikum offered by the Scientific Computing group of the    
 * University of Hamburg, Germany. 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * For any comment or complaint contact the author of the file. 
 *
 */
#ifndef POWERSTATS_H
#define POWERSTATS_H

#include <linux/ioctl.h>

struct interval {
	unsigned int sample;
	unsigned int update;
};

#define PWRS_IOC_MAGIC 0xC1
#define PWRS_IOC_GET_INTERVAL _IOR(PWRS_IOC_MAGIC, 0, struct interval)
#define PWRS_IOC_SET_INTERVAL _IOW(PWRS_IOC_MAGIC, 1, struct interval)

#endif

