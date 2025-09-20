#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Load XDP program from object file
struct bpf_object* load_xdp_program(const char *filename) {
    struct bpf_object *obj;
    int err;

    obj = bpf_object__open(filename);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed: %s\n", filename);
        return NULL;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed: %s\n", strerror(-err));
        bpf_object__close(obj);
        return NULL;
    }

    printf("XDP program loaded successfully from %s\n", filename);
    return obj;
}

// Attach XDP program to network interface
int attach_xdp_program(const char *ifname, int prog_fd, __u32 flags) {
    int ifindex;
    struct bpf_program *prog;
    struct bpf_object *obj;
    int err;

    // Get interface index
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "ERROR: interface %s not found\n", ifname);
        return -1;
    }

    // If prog_fd is -1, we need to get it from the loaded program
    if (prog_fd == -1) {
        fprintf(stderr, "ERROR: program file descriptor not provided\n");
        return -1;
    }

    // Attach XDP program
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, flags);
    if (err < 0) {
        fprintf(stderr, "ERROR: failed to attach XDP program to interface %s: %s\n", 
                ifname, strerror(-err));
        return err;
    }

    printf("XDP program attached to interface %s (index %d) with flags 0x%x\n", 
           ifname, ifindex, flags);
    return 0;
}

// Detach XDP program from network interface
int detach_xdp_program(const char *ifname) {
    int ifindex;
    int err;

    // Get interface index
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "ERROR: interface %s not found\n", ifname);
        return -1;
    }

    // Detach XDP program
    err = bpf_set_link_xdp_fd(ifindex, -1, 0);
    if (err < 0) {
        fprintf(stderr, "ERROR: failed to detach XDP program from interface %s: %s\n", 
                ifname, strerror(-err));
        return err;
    }

    printf("XDP program detached from interface %s\n", ifname);
    return 0;
}

// Update service rule in XDP map
int update_service_rule_xdp(int map_fd, __u32 key, void *rule) {
    int err;

    err = bpf_map_update_elem(map_fd, &key, rule, BPF_ANY);
    if (err < 0) {
        fprintf(stderr, "ERROR: failed to update service rule in XDP map: %s\n", strerror(-err));
        return err;
    }

    return 0;
}

// Get XDP statistics from map
int get_xdp_stats(int map_fd, void *stats) {
    __u32 key = 0;
    int err;

    err = bpf_map_lookup_elem(map_fd, &key, stats);
    if (err < 0) {
        fprintf(stderr, "ERROR: failed to get XDP statistics: %s\n", strerror(-err));
        return err;
    }

    return 0;
}

// Close BPF object and free resources
void close_bpf_object(struct bpf_object *obj) {
    if (obj) {
        bpf_object__close(obj);
    }
}

// Get map file descriptor by name
int get_map_fd_by_name(struct bpf_object *obj, const char *name) {
    struct bpf_map *map;

    map = bpf_object__find_map_by_name(obj, name);
    if (!map) {
        fprintf(stderr, "ERROR: failed to find map %s\n", name);
        return -1;
    }

    return bpf_map__fd(map);
}

// Get program file descriptor by section name
int get_prog_fd_by_name(struct bpf_object *obj, const char *section_name) {
    struct bpf_program *prog;

    prog = bpf_object__find_program_by_name(obj, section_name);
    if (!prog) {
        fprintf(stderr, "ERROR: failed to find program %s\n", section_name);
        return -1;
    }

    return bpf_program__fd(prog);
}