# Powerstats
Powerstats Kernel Module
Author: Björn Brömstrup, Alexander Koglin

Displays the C-states of **ALL** CPU cores.

# Description

This program performs periodic measurements of the processors C-state residency and makes them accessible in /proc/powerstats. It can't deal with hotswapping CPUs and there are some dangerous assumptions about the size of the buffers.

A thread reads the contents of the processors MSRs responsible for tracking C-state residency every period. From this the C-state residency in the time between the last two measurements is calculated and written into a char buffer on a per-thousand basis.
 
# Background 
This file is part of the course material „Kernel Programming“ Praktikum offered by the Scientific Computing group of the	 
University of Hamburg, Germany at the German Climate Computing Center (DKRZ). 

# License
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License version 2 as published by the Free Software Foundation. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of ERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

