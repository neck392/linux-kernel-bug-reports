# FUSE-over-io_uring KASAN UAF

This directory contains materials for a Linux kernel bug report.

- Kernel: upstream v7.1-rc6
- Git head: e43ffb69e0438cddd72aaa30898b4dc446f664f8
- Target file: fs/fuse/dev_uring.c
- Crash: KASAN slab-use-after-free in fuse_uring_copy_to_ring()

Files:

- `repro_fuse_uring_uaf_userns.c`: C reproducer
- `clean_userns_report_rc6.txt`: full symbolized log
- `kernel-config-v7.1-rc6.config`: kernel config used for reproduction

