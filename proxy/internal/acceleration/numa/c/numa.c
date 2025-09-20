#include <sys/syscall.h>
#include <unistd.h>
#include <numa.h>
#include <numaif.h>
#include <errno.h>
#include <stdlib.h>

// Wrapper functions for NUMA system calls to handle potential missing symbols

int get_mempolicy_wrapper(int *policy, unsigned long *nmask, unsigned long maxnode, void *addr, unsigned long flags) {
    return syscall(SYS_get_mempolicy, policy, nmask, maxnode, addr, flags);
}

int set_mempolicy_wrapper(int policy, unsigned long *nmask, unsigned long maxnode) {
    return syscall(SYS_set_mempolicy, policy, nmask, maxnode);
}

int mbind_wrapper(void *start, unsigned long len, int policy, unsigned long *nmask, unsigned long maxnode, unsigned flags) {
    return syscall(SYS_mbind, start, len, policy, nmask, maxnode, flags);
}

long get_numa_node_of_cpu(int cpu) {
    return numa_node_of_cpu(cpu);
}

int migrate_pages_wrapper(int pid, unsigned long maxnode, unsigned long *old_nodes, unsigned long *new_nodes) {
    return syscall(SYS_migrate_pages, pid, maxnode, old_nodes, new_nodes);
}

void *numa_alloc_onnode_wrapper(size_t size, int node) {
    if (numa_available() < 0) {
        return malloc(size);
    }
    return numa_alloc_onnode(size, node);
}

void numa_free_wrapper(void *start, size_t size) {
    if (numa_available() < 0) {
        free(start);
        return;
    }
    numa_free(start, size);
}