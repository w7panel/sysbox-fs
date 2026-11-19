# Graceful FUSE session recovery

`--session-recovery` requires kernel BTF, the `fuse_get_req` kprobe,
read syscall tracepoints, BPF ring buffers, pidfds, openat2 and the new mount API.
The service must run under systemd with `FileDescriptorStoreMax` enabled,
`FileDescriptorStorePreserve=yes`, and `Service.DumpFileDescriptorStore` support.
Unsupported hosts fail startup explicitly.

On graceful stop, FS drains registration and seccomp requests, quiesces FUSE
reads/writes, checkpoints registered containers and their original mount policy,
and detaches host FUSE mounts. Systemd retains seccomp listeners. Mgr separately
checkpoints its container, volume, clone and shiftfs ownership without deleting
live resources. Live-session restoration requires the same boot and a clean stop. After a host
reboot, mgr archives its previous work directories (without deleting data or
touching snapshotter storage) and initializes fresh kernel state. The archive
path is logged for explicit data recovery.

On startup, FS recreates registered views and listeners. BPF reports ENOTCONN/EIO
on checkpointed FUSE devices, deduplicated per namespace/device for one second.
The helper pins the target namespace and root, clones only the matching sysboxfs
mounts, retains their access flags and overlays the old mounts. A minute fallback
checks registered containers and mount namespaces in their cgroup subtrees; it
does not scan unrelated host processes. New opens
recover; already-open descriptors remain attached to the disconnected session.
No host `/proc` passthrough is used.

This is same-boot graceful replacement, not crash recovery. A dirty checkpoint,
PID reuse, unknown prior mounts, incomplete registration, a shared parent of a
replacement target, unsupported child-mount propagation, or a replacement
hiding child mounts is rejected. The first installation over a
legacy daemon requires recreating its affected containers: that daemon has neither
a checkpoint nor retained listeners. Subsequent restart validation must preserve
Pod UIDs and process identities, not recreate Pods to mask a recovery failure.

Regenerate the checked-in CO-RE objects with clang and libbpf headers using
`go generate ./recovery` on the target architecture. Both architectures use
`recovery/bpf/faults.c`; no host-specific vmlinux header is embedded.

Local kernel tests (in addition to ordinary `go test -race ./...`):

```sh
SYSBOX_RECOVERY_PRIVILEGED=1 go test -race ./recovery -v
```

They use isolated FUSE servers and namespaces, verify first-fault and expired-cooldown
deduplication under concurrent reads, batch recovery of two independent devices,
new-open recovery, stale-descriptor failure, mount flags and retry idempotency.
