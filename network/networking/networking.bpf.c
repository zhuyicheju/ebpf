// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include"vmlinux.h"
#include<bpf/bpf_helpers.h>
#include<bpf/bpf_endian.h>
#include<bpf/bpf_tracing.h>
#include<bpf/bpf_core_read.h>
#include"networking.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//key: pid
//value: cgroup_id
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} pid_to_cgroupid SEC(".maps");

//key: cgroup_id
//value: net_cost
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} cgroup_net_cost SEC(".maps");

///key: cgroup_id
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);    
	__type(key, __u64);     
	__type(value, struct cgroup_gained); 
} cgroup_global_cost SEC(".maps");

//key: cgroup_id
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);    
	__type(key, __u64);     
	__type(value, struct throttle_status); 
} cgroup_is_throttled SEC(".maps");

//key: pid
//value: start_cpu_time
//to store the time when the process go into netif_receive_skb
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192); 
    __type(key, __u32);       
    __type(value, __u64);     
} packet_cost_start_rx SEC(".maps");

//key: skb pointer
//value: start_cpu_time
//to store the time when the process go into dev_queue_xmit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u64);
} packet_cost_start_tx SEC(".maps");

//value: cgroup_id
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    // it should be large enough to store all the connections
    __uint(max_entries, 65536);
    __type(key, struct connection_info); 
    __type(value, __u64);                
} connection_to_cgroupid SEC(".maps");


//get cgroup id from sock
//these structs are from Linux 6.8.0-58-generic
static __always_inline __u64 get_cgroup_id_from_sock_core(struct sock *sk)
{
    if (!sk) return 0;

    struct cgroup *cgrp = NULL;
    __u64 id = 0;

    bool cgrp_data_exists = bpf_core_field_exists(sk->sk_cgrp_data);
    if (cgrp_data_exists) {
        bool cgrp_ptr_exists = bpf_core_field_exists(sk->sk_cgrp_data.cgroup);
        if (cgrp_ptr_exists) {
            cgrp = BPF_CORE_READ(sk, sk_cgrp_data.cgroup);
        } else {
            bpf_printk("Field 'cgroup' not found in 'sock_cgroup_data'\n");
        }
    } else {
        bpf_printk("Field 'sk_cgrp_data' not found in 'sock'\n");
    }

    if(cgrp) {
        bool id_exists = bpf_core_field_exists(cgrp->kn->id);
        if(id_exists) {
            id = BPF_CORE_READ(cgrp, kn, id);
        } else {
            bpf_printk("Field 'id' not found in 'cgroup'\n");
        }
    }else {
        bpf_printk("Failed to obtain valid cgroup pointer\n");
    }

    return id;
}


static __always_inline void update_connection_map(struct sock *sk, __u64 cgroup_id) 
{
    if (!sk || cgroup_id == 0) {
        return;
    }

    struct connection_info conn_key = {0};
    struct sock_common *skc = &sk->__sk_common;

    // read the protocol
    conn_key.protocol = BPF_CORE_READ(sk, sk_protocol);
    if (conn_key.protocol != IPPROTO_TCP && conn_key.protocol != IPPROTO_UDP) return;

    __be32 remote_ip = BPF_CORE_READ(skc, skc_daddr);       
    __be32 local_ip  = BPF_CORE_READ(skc, skc_rcv_saddr);  
    __be16 remote_port = BPF_CORE_READ(skc, skc_dport);    
    __be16 local_port = BPF_CORE_READ(skc, skc_num);       
    local_port = bpf_htons(local_port);
    conn_key.saddr = remote_ip;
    conn_key.daddr = local_ip;
    conn_key.sport = remote_port;
    conn_key.dport = local_port;

    int ret = bpf_map_update_elem(&connection_to_cgroupid, &conn_key, &cgroup_id, BPF_ANY);
    if(ret != 0) {
        bpf_printk("Failed to update connection_to_cgroupid map: %d\n", ret);
    }
}

//delete connection when socket is closed
static __always_inline void delete_connection_map(struct sock *sk) 
{
    if (!sk) return;

   u16 protocol = BPF_CORE_READ(sk, sk_protocol);
   if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
       return;
   }

   struct connection_info conn_key = {0};
   struct sock_common *skc = &sk->__sk_common;

   conn_key.protocol = protocol;
   conn_key.saddr = BPF_CORE_READ(skc, skc_daddr);       
   conn_key.daddr = BPF_CORE_READ(skc, skc_rcv_saddr);  
   conn_key.sport = BPF_CORE_READ(skc, skc_dport);    
   conn_key.dport = bpf_htons(BPF_CORE_READ(skc, skc_num)); 


   bpf_map_delete_elem(&connection_to_cgroupid, &conn_key);
}

//TCP server accept connection, inet_csk_accept returns when a new socket is created
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(trace_accept_exit, struct sock *newsk)
{
    if (!newsk) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u64 *cgroup_id_ptr;
    __u64 cgroup_id;

    cgroup_id_ptr = bpf_map_lookup_elem(&pid_to_cgroupid, &pid);
    if (!cgroup_id_ptr || *cgroup_id_ptr == 0) return 0;
    cgroup_id = *cgroup_id_ptr;

    update_connection_map(newsk, cgroup_id);

    return 0;
}

//TCP client connect
SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(trace_connect_exit, int ret)
{
    if (ret != 0) return 0;

    // first parameter of tcp_v4_connect is struct sock *
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u64 *cgroup_id_ptr;
    __u64 cgroup_id;

    cgroup_id_ptr = bpf_map_lookup_elem(&pid_to_cgroupid, &pid);
    if (!cgroup_id_ptr || *cgroup_id_ptr == 0) return 0;
    cgroup_id = *cgroup_id_ptr;

    update_connection_map(sk, cgroup_id);

    return 0;
}

//receive UDP packet for the first time
//it's hard to establish a connection between package and cgroup when using UDP and the server is only receiving, because there isn't an explicit accept() call.
//So we have to assume that the server would send something to the client.
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk) return 0;

    struct sock_common *skc = &sk->__sk_common;
    __be32 daddr = BPF_CORE_READ(skc, skc_daddr);
    __be16 dport = BPF_CORE_READ(skc, skc_dport);
    if (daddr == 0 || dport == 0) return 0;

    // check if the connection already exists
    struct connection_info conn_key = {0};
    conn_key.protocol = IPPROTO_UDP;
    conn_key.saddr = daddr; // Remote IP
    conn_key.daddr = BPF_CORE_READ(skc, skc_rcv_saddr); // Local IP
    conn_key.sport = dport; // Remote Port
    conn_key.dport = bpf_htons(BPF_CORE_READ(skc, skc_num)); // Local Port

    __u64 *existing_cgroup_id_ptr = bpf_map_lookup_elem(&connection_to_cgroupid, &conn_key);
    if (existing_cgroup_id_ptr) return 0;

    // Well it doesn't exist
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u64 *cgroup_id_ptr;
    __u64 cgroup_id;

    cgroup_id_ptr = bpf_map_lookup_elem(&pid_to_cgroupid, &pid);
    if (!cgroup_id_ptr || *cgroup_id_ptr == 0) return 0;
    cgroup_id = *cgroup_id_ptr;

    update_connection_map(sk, cgroup_id);

    return 0;
}

//the TCP server is closed
SEC("kprobe/inet_csk_destroy_sock") 
int BPF_KPROBE(trace_sock_destroy, struct sock *sk)
{
    delete_connection_map(sk);
    return 0;
}


SEC("kprobe/netif_receive_skb")
int BPF_KPROBE(trace_recv_entry, struct sk_buff *skb)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;

    struct task_struct *task;
    __u64 now, swaptime, cumtime, start_cpu_time;
    task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        bpf_printk("trace_recv_entry: Failed to get task_struct\n");
        return 0;
    }

    now = bpf_ktime_get_ns();

    // se.exec_start: boot time
    swaptime = BPF_CORE_READ(task, se.exec_start);
    // se.sum_exec_runtime: the total time that the task has been executed on the CPU
    cumtime = BPF_CORE_READ(task, se.sum_exec_runtime);

    start_cpu_time = cumtime + (now - swaptime);

    int ret = bpf_map_update_elem(&packet_cost_start_rx, &pid, &start_cpu_time, BPF_ANY);
    if (ret != 0) {
       bpf_printk("trace_recv_entry: Failed to update packet_cost_start map: %d\n", ret);
    }

    return 0;
}

SEC("kretprobe/netif_receive_skb")
int BPF_KRETPROBE(trace_recv_exit, int ret_val)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    struct task_struct *task;
    __u64 now_end, swaptime_end, cumtime_end, end_cpu_time;
    __u64 *start_cpu_time_ptr;
    __u64 cost_ns;


    start_cpu_time_ptr = bpf_map_lookup_elem(&packet_cost_start_rx, &pid);
    if (!start_cpu_time_ptr) {
        bpf_printk("trace_recv_exit: Failed to find start time for pid %u\n", pid);
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();
     if (!task) {
        bpf_printk("trace_recv_exit: Failed to get task_struct\n");
        // clear the map
        bpf_map_delete_elem(&packet_cost_start_rx, &pid);
        return 0;
    }

    now_end = bpf_ktime_get_ns();
    swaptime_end = BPF_CORE_READ(task, se.exec_start);
    cumtime_end = BPF_CORE_READ(task, se.sum_exec_runtime);

    end_cpu_time = cumtime_end + (now_end - swaptime_end);

    if (end_cpu_time < *start_cpu_time_ptr) {
        bpf_printk("trace_recv_exit: CPU time went backwards for pid %u?\n", pid);
        // clear the map
        bpf_map_delete_elem(&packet_cost_start_rx, &pid);
        return 0;
    }
    cost_ns = end_cpu_time - *start_cpu_time_ptr;

    // clear the map
    bpf_map_delete_elem(&packet_cost_start_rx, &pid);
    if (cost_ns > 1000000000) {
        bpf_printk("trace_recv_exit: Cost time is too long for pid %u: %llu ns\n", pid, cost_ns);
        return 0;
    }
    if (cost_ns == 0) {
        return 0;
    }

    
    cgroup_id cgroup_id = 0;
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx); // get skb ptr
    struct iphdr *iph = NULL;
    void *transport_header = NULL;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct connection_info conn_key = {0}; 
    __u64 *cgroup_id_ptr = NULL;

    if (!skb) return 0;

    unsigned short network_offset = BPF_CORE_READ(skb, network_header);
    if (network_offset == 0 || network_offset > 2048) return 0;

    //IPv4 header
    iph = (struct iphdr *)(BPF_CORE_READ(skb, head) + network_offset);
    if(!iph) return 0;

    //safely read the IP header
    __u8 first_byte;
    if (bpf_probe_read_kernel(&first_byte, sizeof(first_byte), iph) != 0) return 0;
    __u8 version = first_byte >> 4; 
    __u8 ihl = first_byte & 0x0F;
    if (version != 4) return 0;
    if (ihl < 5) return 0;
    // check the header length
    __u8 ip_hdr_len = ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return 0;

    conn_key.protocol = BPF_CORE_READ(iph, protocol);
    conn_key.saddr = BPF_CORE_READ(iph, saddr);
    conn_key.daddr = BPF_CORE_READ(iph, daddr);
    
    //define the transport header
    transport_header = (void *)iph + ip_hdr_len;

    //read the port numbers
    if (conn_key.protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)transport_header;
        if (bpf_probe_read_kernel(&conn_key.sport, sizeof(conn_key.sport), &tcph->source) != 0 ||
            bpf_probe_read_kernel(&conn_key.dport, sizeof(conn_key.dport), &tcph->dest) != 0) {
            return 0;
        }
    } else if (conn_key.protocol == IPPROTO_UDP) {
       udph = (struct udphdr *)transport_header;
       if (bpf_probe_read_kernel(&conn_key.sport, sizeof(conn_key.sport), &udph->source) != 0 ||
           bpf_probe_read_kernel(&conn_key.dport, sizeof(conn_key.dport), &udph->dest) != 0) {
           return 0;
       }
    } else {
        return 0;
    }


    cgroup_id_ptr = bpf_map_lookup_elem(&connection_to_cgroupid, &conn_key);
    if(!cgroup_id_ptr) {
        bpf_printk("trace_recv_exit: Failed to find cgroup id for connection\n");
        return 0;
    }
    cgroup_id = *cgroup_id_ptr;
    if(!cgroup_id) return 0;

    __u64 *cost_counter_ptr;
    cost_counter_ptr = bpf_map_lookup_elem(&cgroup_net_cost, &cgroup_id);
    if (!cost_counter_ptr) {
        bpf_printk("trace_recv_exit: Failed to find cost counter for cgroup id %llu\n", cgroup_id);
        return 0;
    }

    //add the cost to local cgroup cost
    (void)__sync_fetch_and_add(cost_counter_ptr, cost_ns);

    return 0;
}


SEC("kprobe/dev_queue_xmit")
int BPF_KPROBE(trace_xmit_entry, struct sk_buff *skb)
{
    if (!skb) return 0;

    struct task_struct *task;
    __u64 now, swaptime, cumtime, start_cpu_time;
    __u64 skb_key = (__u64)skb;
    task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    now = bpf_ktime_get_ns();
    swaptime = BPF_CORE_READ(task, se.exec_start);
    cumtime = BPF_CORE_READ(task, se.sum_exec_runtime);
    start_cpu_time = cumtime + (now - swaptime);

    
    bpf_map_update_elem(&packet_cost_start_tx, &skb_key, &start_cpu_time, BPF_ANY);

    return 0;
}

SEC("kretprobe/dev_queue_xmit")
int BPF_KRETPROBE(trace_xmit_exit, int ret)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (!skb) return 0;

    __u64 skb_key = (__u64)skb;
    __u64 *start_cpu_time_ptr;
    __u64 cost_ns;
    struct task_struct *task;
    __u64 now_end, swaptime_end, cumtime_end, end_cpu_time;
    struct sock *sk = NULL;
    __u64 cgroup_id = 0;
    __u64 *cost_counter_ptr;

    
    start_cpu_time_ptr = bpf_map_lookup_elem(&packet_cost_start_tx, &skb_key);
    if (!start_cpu_time_ptr) 
    {
        bpf_printk("trace_xmit_exit: Failed to find start time for skb %p\n", skb);
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        bpf_map_delete_elem(&packet_cost_start_tx, &skb_key);
        return 0;
    }

    now_end = bpf_ktime_get_ns();
    swaptime_end = BPF_CORE_READ(task, se.exec_start);
    cumtime_end = BPF_CORE_READ(task, se.sum_exec_runtime);
    end_cpu_time = cumtime_end + (now_end - swaptime_end);

    if (end_cpu_time < *start_cpu_time_ptr) {
        bpf_map_delete_elem(&packet_cost_start_tx, &skb_key);
        return 0;
    }

    cost_ns = end_cpu_time - *start_cpu_time_ptr;
    bpf_map_delete_elem(&packet_cost_start_tx, &skb_key);
    if (cost_ns == 0) return 0;


    sk = BPF_CORE_READ(skb, sk);
    if (sk) {
        cgroup_id = get_cgroup_id_from_sock_core(sk);
        if (cgroup_id == 0) {
            bpf_printk("trace_xmit_exit: Failed to get cgroup from sk\n");
            return 0; 
        }
    } else {
        bpf_printk("trace_xmit_exit: skb->sk is NULL\n");
        return 0;
    }

    
    cost_counter_ptr = bpf_map_lookup_elem(&cgroup_net_cost, &cgroup_id);
    if (!cost_counter_ptr) {
        bpf_printk("trace_xmit_exit: Failed lookup cgroup_net_cost for cgid %llu\n", cgroup_id);
        return 0;
    }

    (void)__sync_fetch_and_add(cost_counter_ptr, cost_ns);

    return 0;
}


