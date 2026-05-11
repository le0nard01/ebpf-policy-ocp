// Blocks creation of AF_ALG sockets by overriding __sys_socket return value.
#include <linux/types.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_ALG 38
#define EPERM 1

SEC("kprobe/__sys_socket")
int BPF_KPROBE(block_af_alg_socket, int family, int type, int protocol)
{
    if (family == AF_ALG) {
        bpf_override_return(ctx, -EPERM);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
