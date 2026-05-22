Project Overview & SIEM Integration

This project implements an asynchronous, high-performance Web Application Firewall (WAF) Engine and SIEM Detector designed to analyze, normalize, and log malicious HTTP traffic in real time.

Instead of just dropping connections, this engine acts as a cyber threat intelligence source. It generates structured, SIEM-ready JSON logs that can be directly ingested and parsed by enterprise security platforms like Splunk, ElasticSearch (ELK Stack), or QRadar for real-time SOC alerting and incident correlation.

The engine processes incoming traffic through three autonomous defensive layers:

1. Sliding Window Rate-Limiting & Memory GC
An asynchronous Volumetric DoS defense mechanism that tracks requests per IP within a strict 1-second sliding window. It features an isolated background Garbage Collector task that evicts inactive IPs every 60 seconds, eliminating memory leaks and protecting the server from RAM-bloat crashes.

2. Recursive Anti-Bypass Normalization
An advanced decoding pipeline built to defeat multi-layer evasion techniques. Hackers frequently use nested obfuscation like Double URL Encoding or inline SQL comments to bypass static signature filters. This layer runs a recursive loop that strips away all decoding layers until the payload stabilizes into flat lowercase text.

3. Pre-Compiled Signature Inspection
A high-speed regex analysis layer utilizing pre-compiled patterns for minimal CPU cycles. It scans the fully normalized payload for known structural weaponization indicators, specifically targeting SQL Injection (SQLi) authentication bypasses and Remote File Inclusion (RFI) / Path Traversal patterns.

Production Architecture & Limitations!

While this Python-based WAF serves as an excellent proof-of-concept for understanding multi-layer decoding, 
programmatic rate-limiting, and signature analysis, 
implementing it at the core application level in a highload production environment is highly inefficient due to Python's CPU overhead.

In a Top 0.000001% Enterprise infrastructure, security enforcement must be offloaded 
to lower layers of the network stack before traffic ever reaches the application layer:

1. Edge Layer (Cloudflare / AWS Shield / Akamai)
First line of defense against high-volume Volumetric DoS and Distributed DDoS attacks.
Mitigates threat vectors at the global perimeter, long before packets strike internal infrastructure.

3. Reverse Proxy / Ingress Controller (Nginx / Envoy / ModSecurity)
Handles line-rate protocol validation, deep signature inspection, and advanced rate limiting.
 These systems run compiled, high-performance C/C++ or Go binaries designed for sub-millisecond execution.

4. Kernel Space / eBPF (Extended Berkeley Packet Filter)
The bleeding edge of cloud-native security. Utilizes eBPF and XDP (eXpress Data Path) to inspect,
filter, or drop malicious packets directly inside the Linux Kernel space,
bypassing the entire user-space network stack allocation overhead for maximum speed.
