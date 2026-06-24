---
name: TOCTOU vulnerability class research
description: Comprehensive research on TOCTOU (Time-of-Check Time-of-Use) race conditions including key CVEs across VMware, Linux kernel, Windows TCP/IP, Apache Tomcat, and Dirty COW, with assembly-level mechanism and demonstration approaches
type: reference
---

## Key CVEs for TOCTOU demonstrations

### Critical / Actively Exploited
- CVE-2025-22224: VMware ESXi/Workstation VMCI heap overflow via TOCTOU, CVSS 9.3, actively exploited in the wild, VM escape to host VMX process. Patched ESXi 8.0/7.0, Workstation 17.6.3, Fusion 13.6.3
- CVE-2025-38352: Linux kernel POSIX CPU timers TOCTOU race between handle_posix_cpu_timers() and posix_cpu_timer_del(), CVSS ~7.0-7.4, use-after-free, actively exploited on Android. Fixed upstream mid-2025
- CVE-2025-54093: Windows TCP/IP driver TOCTOU race, CVSS 7.0, local privilege escalation. Fix replaced raw pointers with safe offsets
- CVE-2016-5195: Dirty COW Linux kernel copy-on-write race, CVSS 8.4, widely exploited

### High Severity
- CVE-2024-30088: Windows Kernel NtQueryInformationToken TOCTOU, CVSS 7.0, exploited by APT34
- CVE-2024-50379: Apache Tomcat JSP compilation TOCTOU, CVSS 9.8, RCE on case-insensitive FS

### Classic / Historical
- CVE-2003-0813: Multi-threaded RPC TOCTOU causing use-after-free
- CVE-2004-0594: PHP race condition allowing remote code execution
- CVE-2008-1570 / CVE-2008-2958: Symlink-based TOCTOU bypasses
- Classic sendmail: check mailbox attributes then append -- attacker swaps mailbox with symlink to /etc/passwd

## Demonstration approach
- Python: simulate the classic access()/open() file check pattern with a shared variable representing resource state; demonstrate double-check-then-act pattern
- C: demonstrate the actual access()/open() syscall race with symlink swapping between threads
- Assembly explanation: the check (cmp/test instruction) reads memory, then a conditional branch decides whether to proceed; the use (mov/call to open) happens after the branch -- between these instructions, another thread/process can modify the checked resource. System calls (int 0x80 / syscall) are not atomic with each other -- each is a separate context switch into kernel space

## Reliable sources
- CWE-367 on MITRE for canonical definition
- NVD for CVSS scores (403s on direct fetch, use search results instead)
- Broadcom advisory VMSA-2025-0004 for CVE-2025-22224
- CISA KEV catalog for active exploitation status
- SEI CERT C Coding Standard FIO45-C for mitigation patterns
