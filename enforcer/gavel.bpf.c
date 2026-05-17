#ifndef __GAVEL_BPF_C__
#define __GAVEL_BPF_C__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

/*
 * Reference eBPF C program for future bpf2go generation.
 *
 * The shipping Linux prototype currently builds equivalent cilium/ebpf
 * instructions at runtime in ebpf_linux.go. Keep this file as design reference
 * until generated objects replace the runtime-generated loader.
 */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // PID
    __type(value, __u8);  // IsMonitored (0 or 1)
} monitored_pids SEC(".maps");

SEC("sockops")
int gavel_redirect_handler(struct bpf_sock_ops *skops)
{
    __u32 pid = skops->calling_context_pid;
    __u8 *monitored = bpf_map_lookup_elem(&monitored_pids, &pid);

    /* If this PID is marked for Gavel Enforcement */
    if (monitored && *monitored == 1) {
        /* Only intercept TCP Connect events */
        if (skops->op == BPF_SOCK_OPS_TCP_CONNECT_CB) {
            /* 
             * Logic for transparent redirection:
             * We can modify skops->remote_ip4 and skops->remote_port here
             * to force the connection to the Gavel Proxy (e.g. 127.0.0.1:8080)
             * instead of its original destination.
             */
            
            // Reference-only: log the interception in this C version.
            bpf_printk("Gavel Shield: Intercepting connection from Monitored PID %d\n", pid);
            
            /* 
             * Implementation detail: v3.0 will use sk_msg or TPROXY 
             * for full transparent stream redirection without app knowledge.
             */
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
#endif
