// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<unistd.h>
#include<signal.h>
#include<time.h>
#include<sys/resource.h>
#include<sys/sysinfo.h>
#include<bpf/libbpf.h>
#include<bpf/bpf.h>
#include"networking.h"
//#include"networking.skel.h"

static struct networking_bpf *skel = NULL;
//control whether the main loop should exit
static volatile bool exiting = false;
static int pid_map_fd = -1;
static int cost_map_fd = -1;
static int deduct_map_fd = -1;
static int throttle_map_fd = -1;
static int cpus_num = 0;