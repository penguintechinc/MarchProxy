#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_SERVICES 1024
#define MAX_CONNECTIONS 65536

// Service rule structure
struct service_rule {
    __u32 service_id;
    __u32 ip_addr;
    __u16 port;
    __u8 protocol;
    __u8 action; // 0=drop, 1=pass, 2=redirect
    __u32 redirect_ip;
    __u16 redirect_port;
    __u8 auth_required;
    __u8 reserved;
};

// Connection tracking entry
struct connection_entry {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 state; // 0=new, 1=established, 2=closing
    __u64 timestamp;
    __u64 packets;
    __u64 bytes;
};

// Statistics structure
struct xdp_stats {
    __u64 total_packets;
    __u64 passed_packets;
    __u64 dropped_packets;
    __u64 redirected_packets;
    __u64 tcp_packets;
    __u64 udp_packets;
    __u64 other_packets;
    __u64 malformed_packets;
    __u64 last_update;
};

// BPF maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct service_rule);
    __uint(max_entries, MAX_SERVICES);
} service_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64); // connection 5-tuple hash
    __type(value, struct connection_entry);
    __uint(max_entries, MAX_CONNECTIONS);
} connection_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct xdp_stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

// Helper function to calculate 5-tuple hash
static __always_inline __u64 calc_connection_hash(__u32 src_ip, __u32 dst_ip, 
                                                  __u16 src_port, __u16 dst_port, __u8 protocol) {
    return ((__u64)src_ip << 32) | dst_ip | ((__u64)src_port << 16) | dst_port | protocol;
}

// Helper function to update statistics
static __always_inline void update_stats(__u32 stat_type) {
    __u32 key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats)
        return;

    switch (stat_type) {
        case 0: // total packets
            __sync_fetch_and_add(&stats->total_packets, 1);
            break;
        case 1: // passed packets
            __sync_fetch_and_add(&stats->passed_packets, 1);
            break;
        case 2: // dropped packets
            __sync_fetch_and_add(&stats->dropped_packets, 1);
            break;
        case 3: // redirected packets
            __sync_fetch_and_add(&stats->redirected_packets, 1);
            break;
        case 4: // TCP packets
            __sync_fetch_and_add(&stats->tcp_packets, 1);
            break;
        case 5: // UDP packets
            __sync_fetch_and_add(&stats->udp_packets, 1);
            break;
        case 6: // other packets
            __sync_fetch_and_add(&stats->other_packets, 1);
            break;
        case 7: // malformed packets
            __sync_fetch_and_add(&stats->malformed_packets, 1);
            break;
    }
}

// Helper function to lookup service rule
static __always_inline struct service_rule* lookup_service(__u32 ip, __u16 port, __u8 protocol) {
    // Create a simple key from IP, port, and protocol
    __u32 key = (ip & 0xFFFFFF00) | protocol; // Use subnet + protocol as key
    return bpf_map_lookup_elem(&service_rules, &key);
}

// Helper function to update connection tracking
static __always_inline void update_connection_tracking(__u32 src_ip, __u32 dst_ip,
                                                      __u16 src_port, __u16 dst_port,
                                                      __u8 protocol, __u64 timestamp) {
    __u64 hash = calc_connection_hash(src_ip, dst_ip, src_port, dst_port, protocol);
    
    struct connection_entry *conn = bpf_map_lookup_elem(&connection_table, &hash);
    if (conn) {
        // Update existing connection
        __sync_fetch_and_add(&conn->packets, 1);
        conn->timestamp = timestamp;
    } else {
        // Create new connection entry
        struct connection_entry new_conn = {
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .src_port = src_port,
            .dst_port = dst_port,
            .protocol = protocol,
            .state = 0, // new
            .timestamp = timestamp,
            .packets = 1,
            .bytes = 0,
        };
        bpf_map_update_elem(&connection_table, &hash, &new_conn, BPF_ANY);
    }
}

// Main XDP program
SEC("xdp")
int xdp_marchproxy_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Update total packets counter
    update_stats(0);
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) {
        update_stats(7); // malformed
        return XDP_DROP;
    }
    
    // Only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        update_stats(6); // other protocols
        return XDP_PASS;
    }
    
    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        update_stats(7); // malformed
        return XDP_DROP;
    }
    
    // Verify IP header length
    if (ip->ihl < 5) {
        update_stats(7); // malformed
        return XDP_DROP;
    }
    
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u8 protocol = ip->protocol;
    __u16 src_port = 0, dst_port = 0;
    
    // Extract port numbers for TCP/UDP
    void *transport_header = data + sizeof(*eth) + (ip->ihl * 4);
    
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport_header;
        if ((void *)tcp + sizeof(*tcp) > data_end) {
            update_stats(7); // malformed
            return XDP_DROP;
        }
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        update_stats(4); // TCP
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport_header;
        if ((void *)udp + sizeof(*udp) > data_end) {
            update_stats(7); // malformed
            return XDP_DROP;
        }
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
        update_stats(5); // UDP
    } else {
        update_stats(6); // other
        return XDP_PASS; // Pass non-TCP/UDP traffic
    }
    
    // Get current timestamp (approximation)
    __u64 timestamp = bpf_ktime_get_ns();
    
    // Update connection tracking
    update_connection_tracking(src_ip, dst_ip, src_port, dst_port, protocol, timestamp);
    
    // Lookup service rule for destination
    struct service_rule *rule = lookup_service(dst_ip, dst_port, protocol);
    if (!rule) {
        // No rule found, pass to userspace for further processing
        update_stats(1); // passed
        return XDP_PASS;
    }
    
    // Apply service rule
    switch (rule->action) {
        case 0: // drop
            update_stats(2); // dropped
            return XDP_DROP;
            
        case 1: // pass
            update_stats(1); // passed
            return XDP_PASS;
            
        case 2: // redirect
            // For now, just pass to userspace for redirection
            // In a full implementation, we could modify packet headers here
            update_stats(3); // redirected
            return XDP_PASS;
            
        default:
            update_stats(1); // passed
            return XDP_PASS;
    }
}

// XDP program for traffic shaping and rate limiting
SEC("xdp")
int xdp_rate_limiter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Simple rate limiting based on packet size
    __u32 pkt_size = data_end - data;
    
    // Rate limit large packets (>1500 bytes)
    if (pkt_size > 1500) {
        // Simple probability-based dropping for large packets
        __u32 rand = bpf_get_prandom_u32();
        if ((rand % 100) < 10) { // Drop 10% of large packets
            return XDP_DROP;
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;