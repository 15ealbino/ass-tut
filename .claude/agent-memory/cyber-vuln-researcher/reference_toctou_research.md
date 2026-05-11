---
name: TOCTOU vulnerability class research
description: Comprehensive research on TOCTOU (Time-of-Check Time-of-Use) race conditions including key CVEs (CVE-2024-30088, CVE-2024-50379, CVE-2016-5195), assembly-level mechanism, and demonstration approaches
type: reference
---

## Key CVEs for TOCTOU demonstrations
- CVE-2024-30088: Windows Kernel NtQueryInformationToken TOCTOU, CVSS 7.0, exploited by APT34
- CVE-2024-50379: Apache Tomcat JSP compilation TOCTOU, CVSS 9.8, RCE on case-insensitive FS
- CVE-2016-5195: Dirty COW Linux kernel copy-on-write race, CVSS 8.4, widely exploited

## Demonstration approach
- Python: simulate the classic access()/open() file check pattern with a shared variable representing resource state
- C: demonstrate the actual access()/open() syscall race with symlink swapping between threads
- Assembly explanation: the check (cmp/test instruction) reads memory, then a conditional branch decides whether to proceed; the use (mov/call to open) happens after the branch -- between these instructions, another thread/process can modify the checked resource

## Reliable sources
- CWE-367 on MITRE for canonical definition
- NVD for CVSS scores (403s on direct fetch, use search results instead)
- Broadcom/Symantec bulletins for CVE-2024-30088 technical details
- SEI CERT C Coding Standard FIO45-C for mitigation patterns
