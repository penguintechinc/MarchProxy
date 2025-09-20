#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
};

// Initialize DPDK EAL
int init_dpdk_eal(int argc, char **argv) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        printf("Error with EAL initialization\n");
        return -1;
    }
    
    printf("DPDK EAL initialized with %d arguments\n", ret);
    return 0;
}

// Configure a DPDK port
int configure_dpdk_port(uint16_t port_id, uint16_t nb_rx_queues, uint16_t nb_tx_queues) {
    struct rte_eth_conf port_conf = port_conf_default;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    int retval;
    uint16_t q;

    if (!rte_eth_dev_is_valid_port(port_id)) {
        printf("Port %u is not valid\n", port_id);
        return -1;
    }

    retval = rte_eth_dev_info_get(port_id, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", port_id, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    // Configure the Ethernet device
    retval = rte_eth_dev_configure(port_id, nb_rx_queues, nb_tx_queues, &port_conf);
    if (retval != 0) {
        printf("Cannot configure port %u: %s\n", port_id, strerror(-retval));
        return retval;
    }

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &RX_RING_SIZE, &TX_RING_SIZE);
    if (retval != 0) {
        printf("Cannot adjust number of descriptors for port %u: %s\n", port_id, strerror(-retval));
        return retval;
    }

    // Allocate and set up RX queues
    for (q = 0; q < nb_rx_queues; q++) {
        retval = rte_eth_rx_queue_setup(port_id, q, RX_RING_SIZE,
                rte_eth_dev_socket_id(port_id), NULL, NULL);
        if (retval < 0) {
            printf("Cannot setup RX queue %u for port %u: %s\n", q, port_id, strerror(-retval));
            return retval;
        }
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;

    // Allocate and set up TX queues
    for (q = 0; q < nb_tx_queues; q++) {
        retval = rte_eth_tx_queue_setup(port_id, q, TX_RING_SIZE,
                rte_eth_dev_socket_id(port_id), &txconf);
        if (retval < 0) {
            printf("Cannot setup TX queue %u for port %u: %s\n", q, port_id, strerror(-retval));
            return retval;
        }
    }

    printf("Port %u configured with %u RX and %u TX queues\n", port_id, nb_rx_queues, nb_tx_queues);
    return 0;
}

// Create packet mempool
struct rte_mempool* create_packet_mempool(const char *name, unsigned nb_mbufs, unsigned cache_size, uint16_t data_room_size, int socket_id) {
    struct rte_mempool *mbuf_pool;

    mbuf_pool = rte_pktmbuf_pool_create(name, nb_mbufs,
        cache_size, 0, data_room_size, socket_id);

    if (mbuf_pool == NULL) {
        printf("Cannot create mbuf pool: %s\n", rte_strerror(rte_errno));
        return NULL;
    }

    printf("Created mempool '%s' with %u mbufs\n", name, nb_mbufs);
    return mbuf_pool;
}

// Start a DPDK port
int start_dpdk_port(uint16_t port_id) {
    int retval = rte_eth_dev_start(port_id);
    if (retval < 0) {
        printf("Cannot start port %u: %s\n", port_id, strerror(-retval));
        return retval;
    }

    // Enable promiscuous mode
    retval = rte_eth_promiscuous_enable(port_id);
    if (retval != 0) {
        printf("Cannot enable promiscuous mode for port %u: %s\n", port_id, strerror(-retval));
        return retval;
    }

    printf("Port %u started\n", port_id);
    return 0;
}

// Receive burst of packets
uint16_t dpdk_rx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **pkts, uint16_t nb_pkts) {
    return rte_eth_rx_burst(port_id, queue_id, pkts, nb_pkts);
}

// Transmit burst of packets
uint16_t dpdk_tx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **pkts, uint16_t nb_pkts) {
    return rte_eth_tx_burst(port_id, queue_id, pkts, nb_pkts);
}

// Free packets
void dpdk_free_packets(struct rte_mbuf **pkts, uint16_t nb_pkts) {
    uint16_t i;
    for (i = 0; i < nb_pkts; i++) {
        rte_pktmbuf_free(pkts[i]);
    }
}

// Allocate a packet
struct rte_mbuf* dpdk_alloc_packet(struct rte_mempool *mp) {
    return rte_pktmbuf_alloc(mp);
}

// Get packet data pointer
void* get_packet_data(struct rte_mbuf *pkt) {
    return rte_pktmbuf_mtod(pkt, void*);
}

// Get packet length
uint16_t get_packet_len(struct rte_mbuf *pkt) {
    return pkt->pkt_len;
}

// Set packet length
void set_packet_len(struct rte_mbuf *pkt, uint16_t len) {
    pkt->data_len = len;
    pkt->pkt_len = len;
}

// Get link status
int dpdk_get_link_status(uint16_t port_id) {
    struct rte_eth_link link;
    int retval = rte_eth_link_get_nowait(port_id, &link);
    if (retval < 0) {
        printf("Cannot get link status for port %u: %s\n", port_id, strerror(-retval));
        return 0;
    }
    return link.link_status == ETH_LINK_UP ? 1 : 0;
}