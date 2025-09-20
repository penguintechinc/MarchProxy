// Enhanced XDP program for maximum fast-path processing
// This program handles as much as possible in XDP before falling back

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Maximum number of services and rules
#define MAX_SERVICES 1024
#define MAX_RULES 4096
#define MAX_RATE_LIMIT_ENTRIES 8192
#define MAX_CONNECTION_TRACKING 16384

// Action types
#define ACTION_PASS 0
#define ACTION_DROP 1
#define ACTION_REDIRECT_AFXDP 2
#define ACTION_REDIRECT_GO 3
#define ACTION_RATE_LIMIT 4

// Authentication types
#define AUTH_NONE 0
#define AUTH_SIMPLE 1
#define AUTH_COMPLEX 2

// Protocol definitions
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1

// Service definition
struct service {
    __u32 service_id;
    __u32 ip_addr;           // IPv4 address
    __u16 port_start;
    __u16 port_end;
    __u8 protocol;
    __u8 auth_type;
    __u8 requires_tls;
    __u8 allows_websocket;
    __u32 rate_limit_pps;    // Packets per second
    __u32 bandwidth_limit;   // Bytes per second
    __u64 last_activity;
    __u64 packet_count;
    __u64 byte_count;
};

// Advanced rule definition
struct rule {
    __u32 rule_id;
    __u32 src_ip;
    __u32 src_mask;
    __u32 dst_ip;
    __u32 dst_mask;
    __u16 src_port_start;
    __u16 src_port_end;
    __u16 dst_port_start;
    __u16 dst_port_end;
    __u8 protocol;
    __u8 action;
    __u8 auth_required;
    __u8 priority;
    __u32 service_id;
    __u64 packet_count;
    __u64 byte_count;
    __u64 last_match;
};

// Rate limiting entry
struct rate_limit_entry {
    __u32 key;               // IP or service hash
    __u64 last_update;
    __u32 packet_count;
    __u32 byte_count;
    __u32 tokens;            // Token bucket
};

// Connection tracking entry
struct connection {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 state;              // TCP state or UDP activity
    __u64 last_activity;
    __u64 packets_rx;
    __u64 packets_tx;
    __u64 bytes_rx;
    __u64 bytes_tx;
    __u32 service_id;
};

// Simple authentication token (for fast-path auth)
struct auth_token {
    __u32 token_hash;
    __u32 service_id;
    __u64 expiry_time;
    __u8 permissions;
};

// Global statistics
struct global_stats {
    __u64 total_packets;
    __u64 passed_packets;
    __u64 dropped_packets;
    __u64 redirected_afxdp;
    __u64 redirected_go;
    __u64 rate_limited;
    __u64 auth_failures;
    __u64 invalid_packets;
    __u64 last_update;
};

// BPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);           // service_id
    __type(value, struct service);
    __uint(max_entries, MAX_SERVICES);
} services_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);           // rule_id
    __type(value, struct rule);
    __uint(max_entries, MAX_RULES);
} rules_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);           // rate limit key
    __type(value, struct rate_limit_entry);
    __uint(max_entries, MAX_RATE_LIMIT_ENTRIES);
} rate_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);           // connection hash
    __type(value, struct connection);
    __uint(max_entries, MAX_CONNECTION_TRACKING);
} connection_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);           // token hash
    __type(value, struct auth_token);
    __uint(max_entries, 4096);
} auth_tokens_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct global_stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} afxdp_redirect_map SEC(".maps");

// Helper function to calculate hash
static __always_inline __u32 hash_connection(__u32 src_ip, __u32 dst_ip,
                                           __u16 src_port, __u16 dst_port, __u8 proto) {
    return src_ip ^ dst_ip ^ ((__u32)src_port << 16) ^ dst_port ^ proto;
}

// Helper function to get current time in nanoseconds
static __always_inline __u64 get_time_ns() {
    return bpf_ktime_get_ns();
}

// Rate limiting check using token bucket algorithm
static __always_inline int check_rate_limit(__u32 key, __u32 limit_pps) {
    struct rate_limit_entry *entry;
    __u64 now = get_time_ns();
    __u64 time_diff;
    __u32 tokens_to_add;

    entry = bpf_map_lookup_elem(&rate_limit_map, &key);
    if (!entry) {
        // Create new entry
        struct rate_limit_entry new_entry = {
            .key = key,
            .last_update = now,
            .packet_count = 1,
            .byte_count = 0,
            .tokens = limit_pps - 1
        };
        bpf_map_update_elem(&rate_limit_map, &key, &new_entry, BPF_ANY);
        return 1; // Allow
    }

    // Calculate tokens to add (refill bucket)
    time_diff = now - entry->last_update;
    tokens_to_add = (time_diff * limit_pps) / 1000000000ULL; // Convert ns to seconds

    if (tokens_to_add > 0) {
        entry->tokens += tokens_to_add;
        if (entry->tokens > limit_pps) {
            entry->tokens = limit_pps;
        }
        entry->last_update = now;
    }

    // Check if packet is allowed
    if (entry->tokens > 0) {
        entry->tokens--;
        entry->packet_count++;
        return 1; // Allow
    }

    return 0; // Rate limited
}

// Fast-path authentication check
static __always_inline int check_authentication(void *data, void *data_end, __u32 service_id) {
    // For HTTP requests, check for simple token in header
    // This is a simplified version - real implementation would be more robust

    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    char *payload;
    __u32 token_hash = 0;

    // Basic bounds checking
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 1; // Allow non-IP for now

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    if (ip->protocol != PROTO_TCP)
        return 1; // Only check TCP for HTTP auth

    tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
    if ((void *)(tcp + 1) > data_end)
        return 0;

    payload = (char *)tcp + (tcp->doff * 4);
    if (payload + 32 > (char *)data_end)
        return 1; // Not enough data for auth header

    // Look for "Authorization: Bearer " pattern (simplified)
    // In real implementation, this would be more sophisticated
    for (int i = 0; i < 24 && payload + i + 8 < (char *)data_end; i++) {
        if (payload[i] == 'A' && payload[i+1] == 'u' && payload[i+2] == 't' && payload[i+3] == 'h') {
            // Found auth header, extract token hash
            // Simplified token extraction
            token_hash = *(__u32 *)(payload + i + 20);
            break;
        }
    }

    if (token_hash == 0)
        return 0; // No token found

    // Check token in map
    struct auth_token *token = bpf_map_lookup_elem(&auth_tokens_map, &token_hash);
    if (!token)
        return 0; // Invalid token

    // Check expiry and service match
    __u64 now = get_time_ns();
    if (now > token->expiry_time)
        return 0; // Expired token

    if (token->service_id != service_id && token->service_id != 0)
        return 0; // Wrong service

    return 1; // Valid token
}

// Update connection tracking
static __always_inline void update_connection_tracking(__u32 src_ip, __u32 dst_ip,
                                                      __u16 src_port, __u16 dst_port,
                                                      __u8 protocol, __u32 service_id,
                                                      __u32 packet_len) {
    __u64 conn_hash = hash_connection(src_ip, dst_ip, src_port, dst_port, protocol);
    struct connection *conn;
    __u64 now = get_time_ns();

    conn = bpf_map_lookup_elem(&connection_map, &conn_hash);
    if (!conn) {
        // Create new connection
        struct connection new_conn = {
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .src_port = src_port,
            .dst_port = dst_port,
            .protocol = protocol,
            .state = 1,
            .last_activity = now,
            .packets_rx = 1,
            .packets_tx = 0,
            .bytes_rx = packet_len,
            .bytes_tx = 0,
            .service_id = service_id
        };
        bpf_map_update_elem(&connection_map, &conn_hash, &new_conn, BPF_ANY);
    } else {
        // Update existing connection
        conn->last_activity = now;
        conn->packets_rx++;
        conn->bytes_rx += packet_len;
    }
}

// Check if packet needs complex processing (Go fallback)
static __always_inline int needs_complex_processing(void *data, void *data_end,
                                                   struct service *service) {
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    char *payload;

    // Basic checks
    if (!service)
        return 1;

    // Always complex if requires TLS termination
    if (service->requires_tls)
        return 1;

    // Always complex if allows WebSocket (needs upgrade handling)
    if (service->allows_websocket)
        return 1;

    // Always complex if requires complex authentication
    if (service->auth_type == AUTH_COMPLEX)
        return 1;

    // Check for HTTPS (TLS) traffic
    if ((void *)(eth + 1) > data_end)
        return 1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0; // Simple for non-IP

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 1;

    if (ip->protocol == PROTO_TCP) {
        tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end)
            return 1;

        // Check for HTTPS port
        if (bpf_ntohs(tcp->dest) == 443)
            return 1;

        payload = (char *)tcp + (tcp->doff * 4);
        if (payload + 6 <= (char *)data_end) {
            // Check for TLS handshake
            if (payload[0] == 0x16 && payload[1] == 0x03)
                return 1;

            // Check for HTTP methods that might upgrade to WebSocket
            if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T')
                return 1; // GET requests might be WebSocket upgrades
        }
    }

    return 0; // Simple processing
}

// Main packet processing function
static __always_inline int process_packet(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;

    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    __u8 protocol = 0;
    __u32 packet_len = data_end - data;
    __u64 now = get_time_ns();

    // Update global stats
    __u32 stats_key = 0;
    struct global_stats *stats = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (stats) {
        __sync_fetch_and_add(&stats->total_packets, 1);
        stats->last_update = now;
    }

    // Basic Ethernet frame validation
    if ((void *)(eth + 1) > data_end)
        goto drop_invalid;

    // Only process IPv4 for now
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        goto pass_simple;

    // IP header validation
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto drop_invalid;

    src_ip = ip->saddr;
    dst_ip = ip->daddr;
    protocol = ip->protocol;

    // Parse transport layer
    void *transport_header = (void *)ip + (ip->ihl * 4);

    switch (protocol) {
        case PROTO_TCP:
            tcp = (struct tcphdr *)transport_header;
            if ((void *)(tcp + 1) > data_end)
                goto drop_invalid;
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
            break;

        case PROTO_UDP:
            udp = (struct udphdr *)transport_header;
            if ((void *)(udp + 1) > data_end)
                goto drop_invalid;
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
            break;

        case PROTO_ICMP:
            icmp = (struct icmphdr *)transport_header;
            if ((void *)(icmp + 1) > data_end)
                goto drop_invalid;
            // ICMP doesn't have ports, use type/code
            src_port = 0;
            dst_port = icmp->type;
            break;

        default:
            goto pass_simple; // Unknown protocol, pass through
    }

    // Look up matching service
    struct service *service = NULL;
    __u32 service_key;

    // Try to find service by destination IP and port
    for (service_key = 1; service_key <= MAX_SERVICES; service_key++) {
        service = bpf_map_lookup_elem(&services_map, &service_key);
        if (!service)
            continue;

        // Check if packet matches service
        if (service->ip_addr == dst_ip &&
            dst_port >= service->port_start &&
            dst_port <= service->port_end &&
            (service->protocol == 0 || service->protocol == protocol)) {
            break;
        }
        service = NULL;
    }

    if (!service)
        goto pass_simple; // No matching service

    // Update service statistics
    __sync_fetch_and_add(&service->packet_count, 1);
    __sync_fetch_and_add(&service->byte_count, packet_len);
    service->last_activity = now;

    // Check rate limiting
    if (service->rate_limit_pps > 0) {
        __u32 rate_key = src_ip; // Rate limit by source IP
        if (!check_rate_limit(rate_key, service->rate_limit_pps)) {
            if (stats)
                __sync_fetch_and_add(&stats->rate_limited, 1);
            goto drop_rate_limited;
        }
    }

    // Update connection tracking
    update_connection_tracking(src_ip, dst_ip, src_port, dst_port,
                             protocol, service_key, packet_len);

    // Authentication check for simple auth
    if (service->auth_type == AUTH_SIMPLE) {
        if (!check_authentication(data, data_end, service_key)) {
            if (stats)
                __sync_fetch_and_add(&stats->auth_failures, 1);
            goto drop_auth_failure;
        }
    }

    // Determine if packet needs complex processing
    if (needs_complex_processing(data, data_end, service)) {
        // Redirect to Go proxy via AF_XDP
        if (stats)
            __sync_fetch_and_add(&stats->redirected_go, 1);

        // Use queue 0 for complex processing
        __u32 queue_id = 0;
        return bpf_redirect_map(&afxdp_redirect_map, queue_id, 0);
    }

    // Fast-path processing - packet can be handled entirely in XDP
    if (stats)
        __sync_fetch_and_add(&stats->passed_packets, 1);

    return XDP_PASS;

drop_rate_limited:
    if (stats)
        __sync_fetch_and_add(&stats->dropped_packets, 1);
    return XDP_DROP;

drop_auth_failure:
    if (stats)
        __sync_fetch_and_add(&stats->dropped_packets, 1);
    return XDP_DROP;

drop_invalid:
    if (stats) {
        __sync_fetch_and_add(&stats->dropped_packets, 1);
        __sync_fetch_and_add(&stats->invalid_packets, 1);
    }
    return XDP_DROP;

pass_simple:
    if (stats)
        __sync_fetch_and_add(&stats->passed_packets, 1);
    return XDP_PASS;
}

SEC("xdp")
int marchproxy_xdp_main(struct xdp_md *ctx) {
    return process_packet(ctx);
}

char _license[] SEC("license") = "GPL";