// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<unistd.h>
#include<signal.h>
#include<time.h>
#include<sys/resource.h>
#include<bpf/libbpf.h>
#include<bpf/bpf.h>
#include<pthread.h>
#include<dirent.h>
#include<fcntl.h>
#include<sys/stat.h>

#include"networking.h"
#include"networking.skel.h"

struct networking_bpf *skel;
volatile bool running = true;

#define CGROUP_BASE_PATH_V2 "/sys/fs/cgroup"
#define PID_MAP_UPDATE_INTERVAL_SEC 5 
#define MAX_CPUS 256

// catch the SIGINT and SIGTERM signals and kill the program
static void sig_handler(int sig) 
{
    printf("\nCaught signal %d, cleaning up...\n", sig);
    running = false;
}

//print the libbpf log to stderr
static int libbpf_log_print(enum libbpf_print_level level, const char *format, va_list args)
{
    //filter the LIBBPF_DEBUG logs
    if (level > LIBBPF_INFO) return 0;
    // print the log to stderr
    return vfprintf(stderr, format, args);
}

//increase the memory limit
static void bump_memlock_rlimit(void)
{
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
        fprintf(stderr, "Failed to increase memory lock limit: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

int get_num_possible_cpus()
{
    long nprocs = sysconf(_SC_NPROCESSORS_CONF);
    if (nprocs < 0) {
        perror("sysconf for _SC_NPROCESSORS_CONF");
        return -1; 
    }
    return (int)nprocs > MAX_CPUS ? MAX_CPUS : (int)nprocs;
}

__u64 get_cgroup_id_for_pid(pid_t pid)
{
    char proc_cgroup_file[128];
    char cgroup_path_buf[256];
    FILE *f;
    __u64 cgroup_id = 0;

    snprintf(proc_cgroup_file, sizeof(proc_cgroup_file), "/proc/%d/cgroup", pid);
    f = fopen(proc_cgroup_file, "r");
    if (!f) {
        fprintf(stderr, "Failed to open %s: %s\n", proc_cgroup_file, strerror(errno));
        return 0;
    }
    
    if (fgets(cgroup_path_buf, sizeof(cgroup_path_buf), f) != NULL) {
        //find the "0::/" pattern
        char *path_part = strrchr(cgroup_path_buf, ':');
        if (path_part && *(path_part + 1) == '/') { 
            path_part++; 
            char *newline = strchr(path_part, '\n');
            if (newline) *newline = '\0';

            char full_cgroup_path[512];
            snprintf(full_cgroup_path, sizeof(full_cgroup_path), "%s%s", CGROUP_BASE_PATH_V2, path_part);

            struct stat st;
            if (stat(full_cgroup_path, &st) == 0) {
                //use the inode number as the cgroup ID
                cgroup_id = (__u64)st.st_ino;
            } else {
                fprintf(stderr, "Failed to stat cgroup path '%s' for PID %d: %s\n",
                        full_cgroup_path, pid, strerror(errno));
            }
        } else {
            fprintf(stderr, "Could not parse cgroup v2 path format for PID %d: %s\n", pid, cgroup_path_buf);
        }
    }

    fclose(f);
    return cgroup_id;
}

void update_pid_to_cgroupid_map(void)
{
    if (!skel || !skel->maps.pid_to_cgroupid) {
        fprintf(stderr, "BPF skeleton or pid_to_cgroupid map not initialized.\n");
        return;
    }
    int map_fd = bpf_map__fd(skel->maps.pid_to_cgroupid);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get pid_to_cgroupid map FD: %s\n", strerror(errno));
        return;
    }

    DIR *proc_dir;
    struct dirent *entry;
    int updated_count = 0;
    int checked_count = 0;

    proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc for pid_to_cgroupid update");
        return;
    }

    printf("Updating pid_to_cgroupid map...\n");
    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type == DT_DIR) { 
            pid_t pid = atoi(entry->d_name);
            if (pid > 0) { 
                checked_count++;
                __u64 cgroup_id = get_cgroup_id_for_pid(pid);
                if (cgroup_id != 0) { 
                    __u64 existing_cgroup_id = 0;
                    if (bpf_map_lookup_elem(map_fd, &pid, &existing_cgroup_id) == 0) {
                        if (existing_cgroup_id == cgroup_id) {
                            continue; 
                        }
                    }

                    int ret = bpf_map_update_elem(map_fd, &pid, &cgroup_id, BPF_ANY);
                    if (ret != 0) {
                        
                        fprintf(stderr, "Failed to update pid_to_cgroupid for PID %d (cgid %llu): %s\n",
                                pid, cgroup_id, strerror(errno));
                    } else {
                        updated_count++;
                        // printf("Updated PID %d to Cgroup ID %llu\n", pid, cgroup_id);
                    }
                } else {
                    bpf_map_delete_elem(map_fd, &pid);
                }
            }
        }
    }
    closedir(proc_dir);
    printf("Finished pid_to_cgroupid map update. Checked: %d, Updated/Added: %d\n", checked_count, updated_count);
}

void pass_cost_to_kernel(__u64 cgroup_id, __u64 total_period_cost_ns) 
{
    if (total_period_cost_ns > 0) { 
        // printf("Cgroup ID %llu: Aggregated cost for period = %llu ns. Passing to BPF map.\n",
               // cgroup_id, total_period_cost_ns);

        if (!skel || !skel->maps.cgroup_global_cost) {
            fprintf(stderr, "cgroup_global_cost map not available in skeleton.\n");
            return;
        }
        int map_fd = bpf_map__fd(skel->maps.cgroup_global_cost);
        if (map_fd < 0) {
            fprintf(stderr, "Failed to get cgroup_global_cost map FD: %s\n", strerror(errno));
            return;
        }

        struct cgroup_gained new_gained;
        memset(&new_gained, 0, sizeof(new_gained));
        new_gained.net_cost = total_period_cost_ns;

        // Update the map with the new global cost.
        // The BPF program in the kernel will read and clear this.
        int ret = bpf_map_update_elem(map_fd, &cgroup_id, &new_gained, BPF_ANY);
        if (ret != 0) {
            fprintf(stderr, "Failed to update cgroup_global_cost for cgid %llu: %s\n",
                    cgroup_id, strerror(errno));
        }
    }
}

void aggregate_and_pass_costs(void) 
{
    if (!skel || !skel->maps.cgroup_net_cost) {
        fprintf(stderr, "BPF skeleton or cgroup_net_cost map not initialized for aggregation.\n");
        return;
    }
    int cgroup_net_cost_fd = bpf_map__fd(skel->maps.cgroup_net_cost);
    if (cgroup_net_cost_fd < 0) {
        fprintf(stderr, "Failed to get cgroup_net_cost map FD: %s\n", strerror(errno));
        return;
    }

    int num_cpus = get_num_possible_cpus();
    if (num_cpus <= 0) {
        fprintf(stderr, "Cannot aggregate costs: invalid number of CPUs %d\n", num_cpus);
        return;
    }

    __u64 *per_cpu_costs_buffer = calloc(num_cpus, sizeof(__u64));
    if (!per_cpu_costs_buffer) {
        perror("calloc for per_cpu_costs_buffer");
        return;
    }
    // Buffer for clearing the map (all zeros)
    __u64 *zero_costs_buffer = calloc(num_cpus, sizeof(__u64));
    if (!zero_costs_buffer) {
        perror("calloc for zero_costs_buffer");
        free(per_cpu_costs_buffer);
        return;
    }


    // printf("Aggregating network costs...\n");
    __u64 next_cgroup_id_key;
    int iter_ret = 0;

    // iterate through the cgroup_net_cost map
    void *prev_key_ptr = NULL; 

    while (true) {
        iter_ret = bpf_map_get_next_key(cgroup_net_cost_fd, prev_key_ptr, &next_cgroup_id_key);
        if (iter_ret != 0) {
            if (errno == ENOENT) { // No more entries
                break;
            }
            perror("bpf_map_get_next_key failed during cost aggregation");
            break;
        }
        prev_key_ptr = &next_cgroup_id_key; // Use current key as prev_key for next iteration

        // whole cost for this cgroup
        __u64 total_period_cost_ns = 0;

        // Read per-CPU values for this cgroup_id
        int ret = bpf_map_lookup_elem(cgroup_net_cost_fd, &next_cgroup_id_key, per_cpu_costs_buffer);
        if (ret != 0) {
            fprintf(stderr, "Failed to lookup per-cpu costs for cgroup %llu: %s\n",
                    next_cgroup_id_key, strerror(errno));
            continue; // Skip to next cgroup_id
        }

        for (int i = 0; i < num_cpus; i++) {
            total_period_cost_ns += per_cpu_costs_buffer[i];
        }

        if (total_period_cost_ns > 0) {
            pass_cost_to_kernel(next_cgroup_id_key, total_period_cost_ns);

            // Clear the per-CPU costs for this cgroup_id in the BPF map
            ret = bpf_map_update_elem(cgroup_net_cost_fd, &next_cgroup_id_key, zero_costs_buffer, BPF_ANY);
            if (ret != 0) {
                fprintf(stderr, "Failed to clear per-cpu costs for cgroup %llu: %s\n",
                        next_cgroup_id_key, strerror(errno));
            }
        }
    }
    // printf("Finished aggregating network costs.\n");

    free(per_cpu_costs_buffer);
    free(zero_costs_buffer);
}


void *periodic_update_thread_func(void *arg) {
    // printf("Periodic PID map update thread started. Interval: %d sec.\n", PID_MAP_UPDATE_INTERVAL_SEC);
    while (running) {
        sleep(PID_MAP_UPDATE_INTERVAL_SEC);
        if (!running) break;
        update_pid_to_cgroupid_map();
        aggregate_and_pass_costs();
    }
    // printf("Periodic PID map update thread stopped.\n");
    return NULL;
}

int main(int argc, char **argv)
{
    int err;
    pthread_t periodic_thread_id = 0;

    libbpf_set_print(libbpf_log_print);
    bump_memlock_rlimit();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // open the BPF selecton
    skel = networking_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // attach the BPF program to the kernel
    err = networking_bpf__attach(skel);
    if(err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", -err);
        goto cleanup;
    }
    printf("BPF program attached successfully.\n");

    // update the map at the beginning
    update_pid_to_cgroupid_map();

    // start the periodic thread
    if (pthread_create(&periodic_thread_id, NULL, periodic_update_thread_func, NULL) != 0) {
        perror("pthread_create for periodic update thread");
    }

    // Keep main thread alive until signal
    printf("User space controller running. Press Ctrl+C to exit.\n");
    while (running) {
        sleep(1);
    }

    // Wait for periodic thread to finish
    if (periodic_thread_id) {
        printf("Waiting for periodic thread to join...\n");
        pthread_join(periodic_thread_id, NULL);
    }

cleanup:
    printf("Destroying BPF skeleton...\n");
    networking_bpf__destroy(skel);
    printf("Cleanup complete.\n");
    return err < 0 ? -err : 0;
}