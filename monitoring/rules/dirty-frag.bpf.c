#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

#define AF_INET 2
#define AF_INET6 10
#define AF_NETLINK 16
#define AF_RXRPC 33

#define IPPROTO_ESP 50
#define NETLINK_XFRM 6

#define DIRTY_FRAG_RXRPC_SOCKET 1
#define DIRTY_FRAG_ESP_SOCKET 2
#define DIRTY_FRAG_XFRM_NETLINK_SOCKET 3

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, u64);
    __type(value, u64);
} dirty_frag_surface_events_total SEC(".maps");

SEC("kprobe/security_socket_create")
int BPF_KPROBE(kprobe__security_socket_create, int family, int type, int protocol, int kern)
{
    u64 event = 0;

    (void) type;

    if (kern) {
        return 0;
    }

    if (family == AF_RXRPC) {
        event = DIRTY_FRAG_RXRPC_SOCKET;
    } else if ((family == AF_INET || family == AF_INET6) && protocol == IPPROTO_ESP) {
        event = DIRTY_FRAG_ESP_SOCKET;
    } else if (family == AF_NETLINK && protocol == NETLINK_XFRM) {
        event = DIRTY_FRAG_XFRM_NETLINK_SOCKET;
    }

    if (event == 0) {
        return 0;
    }

    increment_map(&dirty_frag_surface_events_total, &event, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
