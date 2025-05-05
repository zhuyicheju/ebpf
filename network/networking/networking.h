#ifndef __NETWORKING_H__
#define __NETWORKING_H__

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

typedef unsigned long long cgroup_id;

struct connection_info {
	unsigned int saddr;     // source ip address
	unsigned int daddr;     // destination ip address
	unsigned short sport;   // source port
	unsigned short dport;   // destination port
	unsigned char protocol; // protocol (TCP/UDP)
	unsigned char _pad[3];  // padding to align to 8 bytes
};

struct cgroup_gained {
    unsigned long long net_cost;
};

struct throttle_status {
    unsigned char is_throttled;
};

#endif 