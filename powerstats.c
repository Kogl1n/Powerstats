/*
 * circmod.c 
 * 
 * Author: Björn Brömstrup, Alexander Koglin
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
 * GNU General Public License for more details.
 *
 * For any comment or complaint contact the author of the file. 
 *
 */

/* This program performs periodic measurements of the processors C-state 
 * residency and makes them accessible in /proc/powerstats. It can't deal 
 * with hotswapping CPUs and there are some dangerous assumptions about the 
 * size of the buffers.
 *
 * A thread reads the contents of the processors MSRs responsible for 
 * tracking C-state residency every period. From this is the C-state 
 * residency in the time between the last two measurements calculated and 
 * written into a char buffer on a per-thousand basis. */ 
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/smp.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <uapi/asm/msr-index.h>
#include "powerstats.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Björn Brömstrup and Alexander Koglin");
MODULE_DESCRIPTION("idle and frequency statistics in /proc/powerstats");
MODULE_VERSION("1.0");

#define INITIAL_SAMPLE_INTERVAL 500
#define INITIAL_UPDATE_INTERVAL 2
#define BUFFER_SIZE(cpu_count, update_interval) \
				((cpu_count) * (update_interval) * 64 + 128)

/* mc0 and mc6 residency have the same msr number as core_c3 and core_c6. 
 * I don't know what the difference is. */
#ifndef MSR_CORE_C1_RESIDENCY
#define MSR_CORE_C1_RESIDENCY 0x660
#endif
#ifndef MSR_MC0_RESIDENCY
#define MSR_MC0_RESIDENCY 0x3fc
#endif
#ifndef MSR_MC6_RESIDENCY
#define MSR_MC6_RESIDENCY 0x3fd
#endif
#ifndef IA32_TIME_STAMP_COUNTER
#define IA32_TIME_STAMP_COUNTER MSR_IA32_TSC
#endif


struct sample {
	volatile unsigned long long cor_c1, cor_c3, cor_c6, cor_c7;
	volatile unsigned long long pkg_c2, pkg_c3, pkg_c6, pkg_c7, pkg_c8,
							pkg_c9, pkg_c10;
	volatile unsigned long long mod_c0, mod_c6;
	volatile unsigned long long tsc;
};

struct buffer {
	struct rw_semaphore rwlock;
	char *mem;
	unsigned long count; //written bytes
	unsigned long size; //overall size
	unsigned long head; //size of header
};

struct measurement {
	struct sample *new;
	struct sample *old;
};

struct procfile {
	/* this spinlock only protects the read access powerstats_read and 
	 * in powerstats_ioctl from the buffer swap in periodic_sample(). 
	 * There is no other instance of multiple threads accessing it. */
	spinlock_t lock;
	struct buffer *front;
	struct buffer *back;
};

enum residency {
	C0 = 0x0, C1 = 0x1, C2 = 0x2, C3 = 0x4, C4 = 0x8, C5 = 0x10,
	C6 = 0x20, C7 = 0x40, C8 = 0x80, C9 = 0x100, C10 = 0x200
};


static unsigned sample_interval = INITIAL_SAMPLE_INTERVAL;
static unsigned update_interval = INITIAL_UPDATE_INTERVAL;

module_param(sample_interval, int, 0);
MODULE_PARM_DESC(sample_interval, "sample interval in ms. Needs to be at "
				"least 10. Is only accurate at 20 or more.");
module_param(update_interval, int, 0);
MODULE_PARM_DESC(update_interval, "count of measurements displayed in "
							"/proc/powerstats");

static struct proc_dir_entry *powerstats_file;
static struct task_struct *thread;

/* This is standard C99. I don't know why I get a warning for this. */
static struct measurement measurement = {0};
static struct procfile procfile = {0};

/* We request the number of online cpus once on init and save it. This is
 * easy, and horribly wrong since cpus can go on- and offline at any time. */
static struct cpumask cpus;
static unsigned cpu_count;
static unsigned cpu_family, cpu_model;
static enum residency pkg_msrs, core_msrs, module_msrs;


/* Maps a logical cpu number to an index based on the cpumask. This is
 * needed, because cpus aren't necessarily numbered in sequence. */
static int cpu_index(int cpu, struct cpumask *mask)
{
	int cpu_i, i = 0;

	for_each_cpu(cpu_i, mask)
		if(cpu == cpu_i)
			return i;
		else
			++i;
	return -1;
}

static void write_measurement_cpu(int cpu, struct buffer *buf,
				struct sample *new, struct sample *old)
{
	unsigned long long interval = new->tsc - old->tsc;

	buf->count += snprintf(buf->mem + buf->count, 4, "%2d ", cpu);

	if(core_msrs & C1)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->cor_c1 - old->cor_c1) / interval);
	if(core_msrs & C3)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->cor_c3 - old->cor_c3) / interval);
	if(core_msrs & C6)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->cor_c6 - old->cor_c6) / interval);
	if(core_msrs & C7)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->cor_c7 - old->cor_c7) / interval);

	if(pkg_msrs & C2)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->pkg_c2 - old->pkg_c2) / interval);
	if(pkg_msrs & C3)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->pkg_c3 - old->pkg_c3) / interval);
	if(pkg_msrs & C6)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->pkg_c6 - old->pkg_c6) / interval);
	if(pkg_msrs & C7)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->pkg_c7 - old->pkg_c7) / interval);
	if(pkg_msrs & C8)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->pkg_c8 - old->pkg_c8) / interval);
	if(pkg_msrs & C9)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->pkg_c9 - old->pkg_c9) / interval);
	if(pkg_msrs & C10)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->pkg_c10 - old->pkg_c10) / interval);

	if(module_msrs & C0)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->mod_c0 - old->mod_c0) / interval);
	if(module_msrs & C6)
		buf->count += snprintf(buf->mem + buf->count, 6, "%4lld ",
				1000*(new->mod_c6 - old->mod_c6) / interval);

	buf->mem[buf->count-1] = '\n';
}

/* Writes the last measurement into buf. */
static int write_measurement(struct timeval *timestamp, struct buffer *buf)
{
	int cpu_i, i = 0;

	down_write(&buf->rwlock);
	if(buf->size - buf->count < cpu_count * 64 + 32) {
		up_write(&buf->rwlock);
		return -1;
	}

	buf->count += snprintf(buf->mem + buf->count, 31, "%ld.%6.6ld\n",
				timestamp->tv_sec, timestamp->tv_usec);
	for_each_cpu(cpu_i, &cpus) {
		write_measurement_cpu(cpu_i, buf, &measurement.new[i],
						&measurement.old[i]);
		++i;
	}
	buf->count += snprintf(buf->mem + buf->count, 2, "\n");
	up_write(&buf->rwlock);

	return 0;
}

/* Reads the MSRs. This is called through on_each_cpu, which ensures it is
 * run atomically. */
static void sample_local_msr(void *info) {
	struct sample *sample = info;
	int i;

	i = cpu_index(smp_processor_id(), &cpus);
	if(i == -1) //oh shit, online cpus have changed
		return;
       	sample = &sample[i];

	if(core_msrs & C1)
	       sample->cor_c1 = native_read_msr(MSR_CORE_C1_RESIDENCY);
	if(core_msrs & C3)
	       sample->cor_c3 = native_read_msr(MSR_CORE_C3_RESIDENCY);
	if(core_msrs & C6)
	       sample->cor_c6 = native_read_msr(MSR_CORE_C6_RESIDENCY);
	if(core_msrs & C7)
	       sample->cor_c7 = native_read_msr(MSR_CORE_C7_RESIDENCY);

	if(pkg_msrs & C2)
	       sample->pkg_c2 = native_read_msr(MSR_PKG_C2_RESIDENCY);
	if(pkg_msrs & C3)
	       sample->pkg_c3 = native_read_msr(MSR_PKG_C3_RESIDENCY);
	if(pkg_msrs & C6)
	       sample->pkg_c6 = native_read_msr(MSR_PKG_C6_RESIDENCY);
	if(pkg_msrs & C7)
	       sample->pkg_c7 = native_read_msr(MSR_PKG_C7_RESIDENCY);
	if(pkg_msrs & C8)
	       sample->pkg_c8 = native_read_msr(MSR_PKG_C8_RESIDENCY);
	if(pkg_msrs & C9)
	       sample->pkg_c9 = native_read_msr(MSR_PKG_C9_RESIDENCY);
	if(pkg_msrs & C10)
	       sample->pkg_c10 = native_read_msr(MSR_PKG_C10_RESIDENCY);

	if(module_msrs & C0)
	       sample->mod_c0 = native_read_msr(MSR_MC0_RESIDENCY);
	if(module_msrs & C6)
	       sample->mod_c6 = native_read_msr(MSR_MC6_RESIDENCY);

	sample->tsc = native_read_msr(IA32_TIME_STAMP_COUNTER);
}

/* Performs measurements */
static int periodic_sample(void *data)
{
	static int i = 0;
	struct timeval timestamp;
	s64 t0, t1;

	while(!kthread_should_stop()) {
		/* measure */
		do_gettimeofday(&timestamp);
		on_each_cpu_mask(&cpus, sample_local_msr, measurement.new, 1);
		write_measurement(&timestamp, procfile.back);

		/* swap measurement buffer and possibly procfile buffer */
		swap(measurement.new, measurement.old);
		if(++i >= update_interval) {
			spin_lock(&procfile.lock);
			swap(procfile.front, procfile.back);
			spin_unlock(&procfile.lock);
			down_write(&procfile.back->rwlock);
			procfile.back->count = procfile.back->head; //reset buf
			up_write(&procfile.back->rwlock);
			i = 0;
		}

		/* sleep */
		t0 = timeval_to_ns(&timestamp);
		do_gettimeofday(&timestamp);
		t1 = timeval_to_ns(&timestamp);
		msleep(sample_interval - (unsigned)((t1-t0) / NSEC_PER_MSEC));
	}

	return 0;
}

/* Detects which C-State MSRs are available. Straight out of Intel's x86 
 * Architecture reference Vol.3 Chapter 35 "Model-specific registers (MSRS)". 
 * Detects only Intel CPUs for now. */
static int detect_cpu(void)
{
	unsigned cpu_sig;
	int cpu_i, cpu_j;

	/* For each group of siblings, we only leave one cpu on which we 
	 * make measurements. */
	cpumask_copy(&cpus, cpu_online_mask);
	for_each_cpu(cpu_i, &cpus)
		for_each_cpu(cpu_j, cpu_sibling_mask(cpu_i))
			if(cpu_i == cpu_j)
				continue;
			else
				bitmap_clear(cpumask_bits(&cpus), cpu_j, 1);
	cpu_count = cpumask_weight(&cpus);

	/* m = model, f = family
	 * xxxx ffff ffff mmmm xxxx ffff mmmm xxxx (binaxy) */
	cpu_sig = cpuid_eax(1);
	cpu_family = (cpu_sig>>8 & 0xf) | (cpu_sig>>16 & 0xff0);
	cpu_model = (cpu_sig>>4 & 0xf) | (cpu_sig>>12 & 0xf0);

	/* MSRs count at the same frequency as the TSC even if it's not 
	 * invariant, which means this program should work autmatically for 
	 * non-invariant TSC. */
#if 0
	/* Check for invariant TSC and exit if it's not supported.
	 * Intel Architecture chapter 16.12.1 "Invariant TSC" */
	cpu_sig = cpuid_edx(0x80000007);
	if(!(cpu_sig & 1<<8))
		goto not_supported;
#endif

	/* Check MSRs */
	pkg_msrs = core_msrs = module_msrs = 0;
	if(cpu_family == 0x06) {
		if(/*certain Atom*/ cpu_model == 0x27) {
			//table 35-5
			//pkg_msrs = C2 | C4 | C6;
			//These MSRs count at 1Mhz instead of TSC frequency, so
			goto not_supported;
		} else if(/*silvermont*/ cpu_model == 0x37 || cpu_model == 0x4a
				|| cpu_model == 0x4d || cpu_model == 0x5a
				|| cpu_model == 0x5d
				|| /*airmont*/ cpu_model == 0x4c) {
			//table 35-6
			pkg_msrs = C6;
			core_msrs = C1 | C6;
		} else if(/*nehalem*/ cpu_model == 0x1a || cpu_model == 0x1e
				|| cpu_model == 0x1f || cpu_model == 0x2e
				|| /*xeon 5600 series*/ cpu_model == 0x25
				|| cpu_model == 0x2c
				|| /*xeon e7 family */ cpu_model == 0x2f) {
			//table 35-11
			pkg_msrs = C3 | C6 | C7;
			core_msrs = C3 | C6;
		} else if(/*sandy bridge*/ cpu_model == 0x2a
				|| cpu_model == 0x2d
				|| /*xeon e3-1200v2*/ cpu_model == 0x3a
				|| /*xeon e5 v2, xeon e7 v2*/ cpu_model == 0x3e
				|| /*xeon e3-1200v3*/ cpu_model == 0x3c
				|| cpu_model == 0x45 || cpu_model == 0x46
				|| /*xeon e5 v3, xeon e7 v3*/ cpu_model == 0x3f
				|| /*core M-5xxx*/ cpu_model == 0x3d
				|| /*sky lake*/ cpu_model == 0x4d) {
			//table 35-16
			pkg_msrs = C2 | C3 | C6 | C7;
			core_msrs = C3 | C6 | C7;
			if(cpu_model == 0x45) //table 35-24
				pkg_msrs |= C8 | C9 | C10;
		} else if(/*xeon phi*/ cpu_model == 0x57) {
			//table 35-30
			pkg_msrs = C2 | C3 | C6 | C7;
			core_msrs = C6;
			module_msrs = C0 | C6;
		} else
			goto not_supported;
	} else
		goto not_supported;

	return 0;

not_supported:
	return -1;
}

/* Sets up the locks and header information. */
static void init_procfile(void)
{
	struct buffer *front = procfile.front;
	struct buffer *back = procfile.back;

	spin_lock_init(&procfile.lock);
	init_rwsem(&procfile.front->rwlock);
	init_rwsem(&procfile.back->rwlock);

	/* header */
	front->count += snprintf(front->mem + front->count, 7,"cpuid ");

	if(core_msrs & C1)
		front->count += snprintf(front->mem+front->count, 8, "cor_c1 ");
	if(core_msrs & C3)
		front->count += snprintf(front->mem+front->count, 8, "cor_c3 ");
	if(core_msrs & C6)
		front->count += snprintf(front->mem+front->count, 8, "cor_c6 ");
	if(core_msrs & C7)
		front->count += snprintf(front->mem+front->count, 8, "cor_c7 ");

	if(pkg_msrs & C2)
		front->count += snprintf(front->mem+front->count, 8, "pkg_c2 ");
	if(pkg_msrs & C3)
		front->count += snprintf(front->mem+front->count, 8, "pkg_c3 ");
	if(pkg_msrs & C6)
		front->count += snprintf(front->mem+front->count, 8, "pkg_c6 ");
	if(pkg_msrs & C7)
		front->count += snprintf(front->mem+front->count, 8, "pkg_c7 ");
	if(pkg_msrs & C8)
		front->count += snprintf(front->mem+front->count, 8, "pkg_c8 ");
	if(pkg_msrs & C9)
		front->count += snprintf(front->mem+front->count, 8, "pkg_c9 ");
	if(pkg_msrs & C10)
		front->count += snprintf(front->mem+front->count, 9, "pkg_c10 ");

	if(module_msrs & C0)
		front->count += snprintf(front->mem+front->count, 8, "mod_c0 ");
	if(module_msrs & C6)
		front->count += snprintf(front->mem+front->count, 8, "mod_c6 ");

	front->mem[front->count-1] = '\n';
	front->count += snprintf(front->mem+front->count, 2, "\n");

	memcpy(back->mem, front->mem, front->count);

	front->head = front->count;
	back->count = front->count;
	back->head = front->count;
	front->size = BUFFER_SIZE(cpu_count, update_interval);
	back->size = BUFFER_SIZE(cpu_count, update_interval);
}


/* generic read */
static ssize_t powerstats_read(struct file *file, char __user *buf,
						size_t count, loff_t *ppos)
{
	struct buffer *buffer;
	unsigned long chunk;
	int err;

	spin_lock(&procfile.lock);
	buffer = procfile.front;
	spin_unlock(&procfile.lock);

	down_read(&buffer->rwlock);

	if(*ppos >= buffer->count || *ppos < 0) {
		err = 0;
		goto fail;
	}

	chunk = buffer->count - *ppos;
	chunk = (count < chunk)? count : chunk;
	if(copy_to_user(buf, buffer->mem + *ppos, chunk)) {
		err = -EFAULT;
		goto fail;
	}

	*ppos += chunk;
	up_read(&buffer->rwlock);
	return chunk;

fail:
	up_read(&buffer->rwlock);
	return err;
}

static long powerstats_ioctl(struct file *file, unsigned int cmd,
							unsigned long arg)
{
	int err = 0;
	struct interval interval;

	switch(cmd) {
	case PWRS_IOC_GET_INTERVAL:
		interval.sample = sample_interval;
		interval.update = update_interval;
		err = copy_to_user((void __user *)arg, &interval,
							sizeof(interval));
		break;
	case PWRS_IOC_SET_INTERVAL: {
		struct buffer *front, *back;
		void *fmem, *bmem;

		err = copy_from_user(&interval, (void __user *)arg,
							sizeof(interval));
		if(err)
			break;
		if(interval.sample < 10 || interval.update < 1) {
			err = -EINVAL;
			break;
		}
		if(interval.update == update_interval) {
			/* just update the sample interval and return */
			sample_interval = interval.sample;
			break;
		}
		/* resize buffers. We malloc one and realloc the other so 
		 * that we can guarantee that either both or none are 
		 * changed. */
		spin_lock(&procfile.lock);
		front = procfile.front;
		back = procfile.back;
		spin_unlock(&procfile.lock);
		down_write(&front->rwlock);
		down_write(&back->rwlock);
		fmem = kmalloc(BUFFER_SIZE(cpu_count, interval.update),
								GFP_KERNEL);
		if(!fmem) {
			err = -ENOMEM;
			break;
		}
		bmem = krealloc(back->mem,
				BUFFER_SIZE(cpu_count, interval.update),
				GFP_KERNEL);
		if(!bmem) {
			kfree(fmem);
			err = -ENOMEM;
			break;
		}
		kfree(front->mem);
		front->mem = fmem;
		back->mem = bmem;
		memcpy(front->mem, back->mem, back->head); //restore header
		front->count = back->head;
		back->count = back->head;
		front->size = BUFFER_SIZE(cpu_count, interval.update);
		back->size = BUFFER_SIZE(cpu_count, interval.update);
		up_write(&back->rwlock);
		up_write(&front->rwlock);
		/* finally, set the new intervals and return */
		sample_interval = interval.sample;
		update_interval = interval.update;
		break;
	}
	}

	return err;
}

static struct file_operations powerstats_fops = {
	.owner = THIS_MODULE,
	.read = powerstats_read,
	.unlocked_ioctl = powerstats_ioctl
};


static int __init powerstats_init(void)
{
	int err;

	/* for sample_interval<20ms msleep is not accurate enough and 
	 * usleep_range should be used instead. */
	if(sample_interval < 10 || update_interval < 1) {
		err = -EINVAL;
		goto fail;
	}

	/* detect cpu, sets all relevant variables */
	if(err = detect_cpu()) {
		printk(KERN_ERR "powerstats: CPU not supported.\n");
		goto fail;
	}

	/* allocate memory */
	measurement.new = kzalloc(cpu_count * sizeof(struct sample), GFP_KERNEL);
	measurement.old = kzalloc(cpu_count * sizeof(struct sample), GFP_KERNEL);
	if(!measurement.new || !measurement.old) {
		err = -ENOMEM;
		goto cleanup_memory;
	}

	procfile.front = kzalloc(sizeof(struct buffer), GFP_KERNEL);
	procfile.back = kzalloc(sizeof(struct buffer), GFP_KERNEL);
	if(!procfile.front || !procfile.back) {
		err = -ENOMEM;
		goto cleanup_memory;
	}

	// this should be more than enough space
	procfile.front->mem = kmalloc(BUFFER_SIZE(cpu_count, update_interval),
								GFP_KERNEL);
	procfile.back->mem = kmalloc(BUFFER_SIZE(cpu_count, update_interval),
								GFP_KERNEL);
	if(!procfile.front->mem || !procfile.back->mem) {
		err = -ENOMEM;
		goto cleanup_memory;
	}

	/* initialize structures */
	init_procfile();

	/* set up /proc file */
	powerstats_file = proc_create("powerstats", S_IRUSR, NULL,
							&powerstats_fops);
	if(!powerstats_file) {
		err = -ENOMEM;
		goto cleanup_memory;
	}

	/* get a starting measurement */
	on_each_cpu(sample_local_msr, measurement.old, 1);

	/* set up thread */
	thread = kthread_run(periodic_sample, NULL, "powerstats");
	if(IS_ERR(thread)) {
		err = PTR_ERR(thread);
		goto cleanup_proc_file;
	}

	/* success */
	return 0;

//cleanup_thread:
	kthread_stop(thread);
cleanup_proc_file:
	proc_remove(powerstats_file);
cleanup_memory:
	kfree(procfile.back->mem);
	kfree(procfile.front->mem);
	kfree(procfile.back);
	kfree(procfile.front);
	kfree(measurement.old);
	kfree(measurement.new);
fail:
	return err;
}

static void __exit powerstats_exit(void)
{
	kthread_stop(thread);

	proc_remove(powerstats_file);

	kfree(procfile.back->mem);
	kfree(procfile.front->mem);
	kfree(procfile.back);
	kfree(procfile.front);
	kfree(measurement.old);
	kfree(measurement.new);
}

module_init(powerstats_init);
module_exit(powerstats_exit);

