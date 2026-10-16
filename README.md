##  $${\color{blue} C++ \space RAW-Socket \space IDS \space & \space Packet  \space Sniffer: \sapce Devlopment \space Reoadmap}$$
# $${\color{blue}VLAN \space Configuration \space Labs \space using \space Cisco \space Packet \space Tracer}$$

**Suggested timeline:** about 11 weeks at 8-10 hours/week each. Compress it if your deadline is tighter.

**Pair workflow:** Split roles (Person A: capture and parsing, Person B: detection engine), then swap in Phase 3. Use Git with feature branches and review each other's pull requests. Reading a partner's pointer arithmetic is great practice.

---

## 0. Prerequisites & Core Concepts (Weeks 1-2)

### C++ skills

| Topic | What to master | Practice task |
|---|---|---|
| Pointers & casting | `reinterpret_cast`, pointer arithmetic, `uint8_t*` buffers | Walk a byte array and print fields by offset |
| Structs | `#pragma pack` / `__attribute__((packed))`, padding, alignment | Compare `sizeof` of packed vs. unpacked structs |
| Bitwise ops | Masks, shifts, flags (`&`, `\|`, `>>`) | Extract the IP version/IHL nibbles and TCP flag bits |
| Endianness | `htons/ntohs/htonl/ntohl` | Write a function that prints a 16-bit value in both byte orders |
| Memory | RAII, `std::vector<uint8_t>`, smart pointers, avoiding buffer overreads | Run everything under AddressSanitizer |
| STL | `unordered_map`, `unordered_set`, `deque`, `chrono` | Needed for state tracking in Phase 2 |
| Build tooling | CMake, `-Wall -Wextra`, `-fsanitize=address,undefined`, GDB | Set up the repo skeleton |

### Networking concepts

- OSI vs. TCP/IP model; Ethernet frame layout (dst MAC, src MAC, EtherType)
- IPv4 header (IHL, protocol, flags/fragment offset, TTL, checksum)
- TCP header (data offset, flags SYN/ACK/FIN/RST/PSH/URG, sequence numbers), the 3-way handshake and teardown
- UDP and ICMP structure (types and codes)
- How `nmap` scans and SYN floods look on the wire (flag patterns)
- Linux specifics: `AF_PACKET` sockets, `CAP_NET_RAW`, promiscuous mode, network interfaces

### Deliverable

A repo with a CMake build, a README, and a small "byte-array parser" demo that decodes a hardcoded Ethernet+IP+TCP packet.

### Resources

- **learncpp.com** (pointers, bitwise, classes)
- **Beej's Guide to Network Programming** (free)
- **TCP/IP Illustrated, Vol. 1** (Stevens) for the header chapters
- **RFC 791** (IP), **RFC 793** (TCP), **RFC 768** (UDP), **RFC 792** (ICMP)
- Man pages: `man 7 packet`, `man 7 raw`, `man 7 netdevice`
- Wireshark: capture normal traffic and inspect every field by hand

---

## Phase 1: The Core Packet Sniffer (Weeks 3-4)

### Week 3: Capture

| Day | Task |
|---|---|
| 1 | Open the socket and receive frames in a loop (see skeleton below) |
| 2 | Bind to a specific interface via `sockaddr_ll` and `if_nametoindex` |
| 3 | Enable promiscuous mode (`PACKET_ADD_MEMBERSHIP` + `PACKET_MR_PROMISC`) |
| 4 | Handle `SIGINT` cleanly (close the socket, print stats) |
| 5 | Parse the Ethernet header, filter by EtherType (IPv4 first, ARP/IPv6 later) |

```cpp
int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
if (sock < 0) { perror("socket"); return 1; }   // needs root or CAP_NET_RAW

uint8_t buf[65536];
while (running) {
    ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, nullptr, nullptr);
    if (n <= 0) continue;
    parse_ethernet(buf, n);
}
```

Tip: instead of running as root, use `sudo setcap cap_net_raw,cap_net_admin=eip ./sniffer`.

### Week 4: Manual header parsing

| Day | Task |
|---|---|
| 1 | IPv4: version, IHL × 4 for the real header length, protocol, src/dst, total length |
| 2 | TCP: ports, flags, seq/ack, data offset × 4 |
| 3 | UDP and ICMP (type/code) |
| 4 | **Bounds checking on every parse** (truncated packets must never crash you) |
| 5 | Pretty printer: `[TCP] 192.168.1.5:443 -> 10.0.0.2:51234 [SYN,ACK] len=60` |

### Technical requirements

- Define your own packed structs first to learn the layouts, then compare with `<netinet/ip.h>` and `<netinet/tcp.h>`.
- Validate lengths before dereferencing: `if (offset + sizeof(tcphdr) > len) return;`
- Optional: verify IP and TCP checksums.
- Cross-check your output against `tcpdump -i <iface> -n` on the same traffic. Your parser should agree with it.
- Design a clean `Packet` struct (parsed fields plus timestamp) now, because Phase 2 consumes it.

### Suggested structure

```
ids/
├─ src/ capture/ parser/ detection/ alert/ main.cpp
├─ include/
├─ tests/
└─ CMakeLists.txt
```

### Deliverable

A sniffer that prints parsed IP/TCP/UDP/ICMP traffic, doesn't crash on malformed input, and matches tcpdump.

---

## Phase 2: Traffic Analysis & Detection Logic (Weeks 5-7)

### Week 5: State-tracking foundations

- Build a per-source-IP tracker: `unordered_map<uint32_t, HostStats>`
- Implement **sliding time windows** (a `deque` of timestamps, or fixed buckets) using `std::chrono::steady_clock`
- Implement **periodic cleanup** of stale entries (otherwise memory grows without bound, itself a DoS vector against your IDS)
- Make thresholds configurable constants (later, a config file)

### Week 6: Port scan detection

| Scan type | Heuristic |
|---|---|
| TCP connect/SYN scan | One source hitting more than N **distinct** destination ports within T seconds, mostly SYN-only packets |
| NULL / FIN / Xmas scans | Flag combinations that never occur in normal traffic: no flags; FIN only; FIN+PSH+URG |
| Horizontal sweep | One source touching the same port on many destination hosts |
| UDP / ICMP sweeps | Many distinct targets or ports with few replies |

Data structure per source: `unordered_set<uint16_t>` of destination ports plus a window start time. Reset or slide the window, and alert once the threshold is crossed.

### Week 7: SYN flood and other floods

- **Rate-based:** SYNs per second from a source (or globally) above a threshold.
- **Half-open ratio:** track SYNs versus completed handshakes (the final ACK). A large, growing gap is the signal.
- **Spoofed-source awareness:** a flood from random source IPs defeats per-IP counting, so also track the **global** SYN rate toward a single destination.
- Add ICMP flood (echo requests per second) as an easy third detector.
- Design a `Detector` interface (`virtual void inspect(const Packet&)`) so each detection is a plug-in class. It's cleaner, testable, and impressive in a report.

### Reducing false positives

- Whitelist known hosts (your gateway, DNS server).
- Use alert cooldowns so one scan doesn't produce 10,000 alerts.
- Tune thresholds against real baseline traffic (browsing, streaming, `apt update`).

### Deliverable

Three or more working detectors with configurable thresholds, cleanup logic, and unit tests that feed crafted `Packet` sequences into each detector.

### Resources

- Snort and Suricata docs (rule concepts such as `flags:S`, `detection_filter`, and thresholding)
- Nmap book chapters on scan types (nmap.org/book)
- Papers/articles on threshold random walk (TRW) scan detection and SYN cookies, for the theory

---

## Phase 3: Alerting, Logging & Performance (Weeks 8-9)

### Week 8: Alerts and logs

- **Console output:** severity levels (INFO/WARN/CRITICAL), ANSI colors, timestamps
- **Alert record:** `{timestamp, severity, type, src_ip, dst_ip, details}`
- **File logging:** append-only log, one line per alert, ideally JSON Lines for easy parsing; add simple size-based rotation
- **Optional PCAP export:** write the offending packets to a `.pcap` file (the format is simple: a global header plus per-packet headers) so you can open it in Wireshark
- **Config file** (INI or JSON): interface, thresholds, whitelist, log path

### Week 9: Performance and multithreading

Only add threads once you've *measured* a need. A clean design:

```
[Capture thread] -> thread-safe queue -> [Analysis thread(s)] -> [Logger thread]
```

- Use `std::thread`, `std::mutex`, and `std::condition_variable` (or a lock-free ring buffer if you want a challenge).
- Keep the capture thread minimal so you don't drop packets. It should copy bytes and enqueue, nothing more.
- Avoid shared mutable state between analyzers (shard by source IP hash if needed).
- Measure dropped packets with `getsockopt(..., PACKET_STATISTICS)`.
- Stretch goals: BPF filters via `SO_ATTACH_FILTER`, `PACKET_MMAP`/`TPACKET_V3` for zero-copy ring buffers, `perf` and `gprof` profiling.

### Deliverable

An IDS that runs continuously, logs structured alerts, shuts down gracefully, and handles a sustained high packet rate without crashing or leaking memory (verify with Valgrind or ASan).

### Resources

- *C++ Concurrency in Action* (Anthony Williams)
- `man 7 packet` (PACKET_STATISTICS, fanout, mmap sections)
- Kernel docs: `Documentation/networking/packet_mmap.txt`

---

## Phase 4: Testing & Validation (Weeks 10-11)

### ⚠️ Safe and legal testing rules

- Test **only** on machines and networks you own or have explicit permission to use.
- Use an isolated lab: two VMs on a host-only network (VirtualBox/VMware/KVM), or Linux **network namespaces with veth pairs** (no VMs needed).
- Never point `hping3 --flood` or `nmap` at university or public infrastructure. Even "just a scan" can violate policy or law.

### Lab setup (namespaces example)

```bash
sudo ip netns add attacker
sudo ip link add veth-a type veth peer name veth-v
sudo ip link set veth-a netns attacker
sudo ip addr add 10.10.0.1/24 dev veth-v && sudo ip link set veth-v up
sudo ip netns exec attacker ip addr add 10.10.0.2/24 dev veth-a
sudo ip netns exec attacker ip link set veth-a up
# Run the IDS on veth-v; launch tools from inside the 'attacker' namespace
```

### Test matrix

| Test | Tool | Expected result |
|---|---|---|
| Baseline traffic | `ping`, `curl`, browsing | **No** alerts (false-positive check) |
| SYN scan | `nmap -sS 10.10.0.1` | Port scan alert |
| Connect scan | `nmap -sT` | Port scan alert |
| Stealth scans | `nmap -sN`, `-sF`, `-sX` | Invalid-flag alerts |
| Slow scan | `nmap -T1` | Probably evades you; document it as a known limitation |
| SYN flood | `hping3 -S -p 80 --flood 10.10.0.1` (lab only) | SYN flood alert |
| ICMP flood | `ping -f 10.10.0.1` (lab only; needs root) | ICMP flood alert |
| Malformed packets | `hping3` with odd flags or fragments | No crash |

### Validation techniques

- **Unit tests** (GoogleTest or Catch2): feed hand-built byte arrays to the parser, including truncated and corrupt ones.
- **Replay testing:** capture traffic with tcpdump, then replay it with `tcpreplay` for repeatable results.
- **Ground truth:** compare your detections to what Suricata or Snort flags on the same pcap.
- **Robustness:** compile with `-fsanitize=address,undefined`, and fuzz the parser (libFuzzer or AFL++). Parsers of untrusted network data are a classic source of vulnerabilities.
- **Metrics to report:** detection rate, false-positive rate, detection latency, CPU usage, and packets dropped at various traffic rates.

### Deliverable

A test report with the test matrix results, screenshots or log excerpts, measured metrics, and a "Limitations & Future Work" section (IPv6, fragment reassembly, encrypted traffic, evasion techniques, slow scans).

---

## Final Checklist

- [ ] Parser is bounds-checked and sanitizer-clean
- [ ] Output matches tcpdump on identical traffic
- [ ] Three or more detectors with configurable thresholds
- [ ] Memory-bounded state with cleanup
- [ ] Structured logs and graceful shutdown
- [ ] Reproducible lab and test suite in the repo
- [ ] README with an architecture diagram, build steps, and legal/ethical notice

## Stretch Goals

IPv6 support, TCP stream reassembly, signature-based rules (a mini-Snort rule parser), ARP spoofing detection, DNS anomaly detection, a web dashboard reading your JSON logs, and eBPF/XDP as a "next-generation capture" comparison.
