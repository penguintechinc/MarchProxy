#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <poll.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE 2048
#define RX_BATCH_SIZE 64
#define TX_BATCH_SIZE 64

// UMEM configuration
static struct xsk_umem_config umem_config = {
    .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
    .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
    .frame_size = FRAME_SIZE,
    .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    .flags = 0,
};

// Socket configuration
static struct xsk_socket_config xsk_config = {
    .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
    .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
    .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
    .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE,
    .bind_flags = 0,
};

// Configure XSK UMEM
int configure_xsk_umem(struct xsk_umem_info *umem_info, void *buffer, uint64_t buffer_size) {
    int ret;

    ret = xsk_umem__create(&umem_info->umem, buffer, buffer_size, 
                          &umem_info->fq, &umem_info->cq, &umem_config);
    if (ret) {
        fprintf(stderr, "ERROR: Can't create UMEM: %s\n", strerror(-ret));
        return ret;
    }

    umem_info->buffer = buffer;
    umem_info->buffer_size = buffer_size;

    printf("AF_XDP: UMEM configured with %lu bytes\n", buffer_size);
    return 0;
}

// Create AF_XDP socket
int create_af_xdp_socket(const char *ifname, int queue_id, struct xsk_socket_info *xsk_info) {
    int ret;
    int ifindex;
    uint32_t prog_id = 0;

    // Get interface index
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "ERROR: interface %s not found\n", ifname);
        return -1;
    }

    // Create XSK socket
    ret = xsk_socket__create(&xsk_info->xsk, ifname, queue_id, 
                            xsk_info->umem->umem, &xsk_info->rx, &xsk_info->tx, &xsk_config);
    if (ret) {
        fprintf(stderr, "ERROR: Can't create XSK socket: %s\n", strerror(-ret));
        return ret;
    }

    // Initialize frame management
    xsk_info->umem_frame_free = NUM_FRAMES;
    xsk_info->outstanding_tx = 0;

    // Initialize frame addresses
    for (int i = 0; i < NUM_FRAMES; i++) {
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;
    }

    printf("AF_XDP: Socket created for interface %s queue %d\n", ifname, queue_id);
    return 0;
}

// Receive and process packets
int rx_and_process(struct xsk_socket_info *xsk_info, int batch_size) {
    uint32_t idx_rx = 0, idx_fq = 0;
    int rcvd, ret;
    uint64_t addr;
    void *pkt;

    // Reserve space in fill queue
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, batch_size, &idx_fq);
    if (ret != batch_size) {
        // Fill queue might be full, try with available space
        if (ret == 0) {
            return 0;
        }
        batch_size = ret;
    }

    // Fill the fill queue with available frames
    for (int i = 0; i < batch_size; i++) {
        if (xsk_info->umem_frame_free == 0) {
            break;
        }
        
        addr = xsk_info->umem_frame_addr[--xsk_info->umem_frame_free];
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq++) = addr;
    }

    // Submit the fill queue entries
    xsk_ring_prod__submit(&xsk_info->umem->fq, batch_size);

    // Receive packets
    rcvd = xsk_ring_cons__peek(&xsk_info->rx, batch_size, &idx_rx);
    if (!rcvd) {
        return 0;
    }

    // Process received packets
    for (int i = 0; i < rcvd; i++) {
        addr = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx + i)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx + i)->len;
        
        // Get packet data
        pkt = xsk_umem__get_data(xsk_info->umem->buffer, addr);
        
        // Simple packet processing - just echo back for now
        // In real implementation, this would parse and filter packets
        
        // For demonstration, we'll just count the packet
        // Real processing would happen here
    }

    // Release received packets
    xsk_ring_cons__release(&xsk_info->rx, rcvd);

    return rcvd;
}

// Transmit packets
int tx_packets(struct xsk_socket_info *xsk_info, int batch_size) {
    uint32_t idx_tx = 0;
    int ret;

    // Check if we have outstanding TX packets to complete
    if (xsk_info->outstanding_tx) {
        uint32_t idx_cq = 0;
        int completed = xsk_ring_cons__peek(&xsk_info->umem->cq, xsk_info->outstanding_tx, &idx_cq);
        
        if (completed > 0) {
            // Reclaim completed frames
            for (int i = 0; i < completed; i++) {
                uint64_t addr = *xsk_ring_cons__comp_addr(&xsk_info->umem->cq, idx_cq + i);
                xsk_info->umem_frame_addr[xsk_info->umem_frame_free++] = addr;
            }
            
            xsk_ring_cons__release(&xsk_info->umem->cq, completed);
            xsk_info->outstanding_tx -= completed;
        }
    }

    // For now, we don't have packets to transmit
    // In a real implementation, this would transmit queued packets
    
    return 0;
}

// Get XSK statistics
uint64_t get_xsk_stats(struct xsk_socket_info *xsk_info, int stat_type) {
    struct xdp_statistics stats;
    socklen_t optlen = sizeof(stats);
    int fd;

    if (!xsk_info || !xsk_info->xsk) {
        return 0;
    }

    fd = xsk_socket__fd(xsk_info->xsk);
    if (getsockopt(fd, SOL_XDP, XDP_STATISTICS, &stats, &optlen) == 0) {
        switch (stat_type) {
            case 0: return stats.rx_dropped;
            case 1: return stats.rx_invalid_descs;
            case 2: return stats.tx_invalid_descs;
            case 3: return stats.rx_ring_full;
            case 4: return stats.rx_fill_ring_empty_descs;
            case 5: return stats.tx_ring_empty_descs;
            default: return 0;
        }
    }

    return 0;
}

// Cleanup XSK socket
void cleanup_xsk(struct xsk_socket_info *xsk_info) {
    if (xsk_info->xsk) {
        xsk_socket__delete(xsk_info->xsk);
        xsk_info->xsk = NULL;
    }
    
    if (xsk_info->umem && xsk_info->umem->umem) {
        xsk_umem__delete(xsk_info->umem->umem);
        xsk_info->umem->umem = NULL;
    }
    
    printf("AF_XDP: Socket cleanup complete\n");
}

// Poll for socket activity
int poll_xsk_socket(struct xsk_socket_info *xsk_info, int timeout_ms) {
    struct pollfd fds[1];
    int ret;

    if (!xsk_info || !xsk_info->xsk) {
        return -1;
    }

    fds[0].fd = xsk_socket__fd(xsk_info->xsk);
    fds[0].events = POLLIN;

    ret = poll(fds, 1, timeout_ms);
    if (ret < 0) {
        return -errno;
    }

    return ret;
}

// Kick TX ring if needed
void kick_tx(struct xsk_socket_info *xsk_info) {
    if (xsk_ring_prod__needs_wakeup(&xsk_info->tx)) {
        sendto(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    }
}

// Kick RX ring if needed
void kick_rx(struct xsk_socket_info *xsk_info) {
    if (xsk_ring_prod__needs_wakeup(&xsk_info->umem->fq)) {
        sendto(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    }
}