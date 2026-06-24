---
name: Use-After-Realloc CVE Reference List
description: Researched CVEs in the use-after-realloc / double-free-via-realloc vulnerability class, with key technical details and sources
type: reference
---

## Use-After-Realloc CVEs Researched (as of 2026-06-24)

### CVE-2023-25136 - OpenSSH Pre-Auth Double Free (CVSS 6.5)
- Affected: OpenSSH 9.1
- Root cause: compat_kex_proposal() frees options.kex_algorithms but returns the freed pointer; kex_assemble_names() frees it again
- Classification: CWE-415 (Double Free), closely related to use-after-realloc pattern
- Key source: Qualys blog, JFrog PoC writeup, openwall oss-security

### CVE-2023-29491 - ncurses Memory Corruption (CVSS 7.8)
- Affected: ncurses < 6.4 20230408
- Root cause: _nc_read_termtype() realloc shrinks allocation, then writes beyond bounds via convert_strings; also stack info leak via tparm()
- Classification: CWE-787 (Out-of-bounds Write)
- Key source: Microsoft "Uncursing the ncurses" blog, Ubuntu security notices

### CVE-2026-33986 - FreeRDP H.264 YUV Buffer Dimension Desync (CVSS 7.5)
- Affected: FreeRDP <= 3.24.1
- Root cause: yuv_ensure_buffer() updates h264->width/height BEFORE realloc loop; if realloc fails, dimensions are inflated but buffer is undersized; next call skips realloc entirely
- Classification: CWE-122 (Heap Buffer Overflow), CWE-131 (Incorrect Buffer Size)
- Key source: GitHub Advisory GHSA-h6qw-wxvm-hf97

### CVE-2026-33984 - FreeRDP ClearCodec resize_vbar_entry (CVSS 7.5)
- Affected: FreeRDP <= 3.24.1
- Root cause: vBarEntry->size updated before realloc; if realloc fails, size inflated, subsequent writes overflow
- Key source: GitHub Advisory GHSA-8469-2xcx-frf6

### CVE-2024-56759 - Linux btrfs COW Use-After-Free
- Affected: Linux kernel btrfs with CONFIG_PREEMPT=y
- Root cause: trace_btrfs_cow_block() called after free_extent_buffer_stale(buf); preemption allows RCU to release buffer before tracepoint fires
- Related to btrfs_realloc_node() in defrag path

## Vulnerability Class Notes
- Use-after-realloc is a subclass of CWE-416 (Use After Free), closely related to CWE-761 and CWE-825 (Expired Pointer Dereference)
- C code demonstrations are always preferable for this class — Python cannot meaningfully express pointer/memory semantics
- The pattern always involves: (1) original allocation, (2) realloc that may move or fail, (3) stale pointer access
