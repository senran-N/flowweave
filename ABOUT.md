# FlowWeave: Weaving Multiple Networks into One Resilient Connection

## Inspiration

Modern devices often have several network connections available—Wi-Fi, cellular data, and sometimes multiple broadband links—yet applications still experience them as separate, fragile paths. A brief outage or network switch can interrupt a tunnel, terminate a long-running transfer, or create a visible pause in real-time traffic.

FlowWeave began with a simple question:

> What if multiple networks could behave like strands of one connection instead of isolated fallbacks?

The goal was to explore whether multipath QUIC could provide three useful properties at once:

1. Keep an existing connection alive when one path fails.
2. Use multiple paths together when additional capacity is available.
3. Reduce loss and tail latency for real-time messages on unreliable networks.

## What FlowWeave Does

FlowWeave is an experimental multipath QUIC transport written in Rust. It establishes one authenticated QUIC connection across multiple network paths, allowing traffic to continue over a healthy path when another becomes unavailable.

The repository includes:

- A fixed-target TCP proxy carried over TLS 1.3 and multipath QUIC.
- A Linux layer-3 VPN prototype supporting IPv4, IPv6, TCP, UDP, and ICMP.
- An experimental redundancy strategy for latency-sensitive datagrams.
- An isolated network laboratory for reproducible delay, bandwidth, loss, and path-failure tests.
- Fair comparisons against Hysteria 2.9.3 and Linux MPTCP.
- Deployment examples, health reporting, identity rotation, and failure recovery tooling.

FlowWeave is currently an experimental system suitable for controlled pilots, not a general-purpose consumer VPN or a production SLA.

## How We Built It

The transport core is built in Rust on a pinned and locally audited version of NoQ, extended with narrowly scoped multipath recovery, feedback, and measurement capabilities. Reliable proxy traffic uses QUIC streams, while real-time messages and tunneled IP packets use QUIC DATAGRAM frames to avoid global reliable head-of-line blocking.

The VPN has separate control and data protocols:

- `FWC1` negotiates protocol versions, capabilities, virtual addresses, MTU limits, and session generations.
- `FWI1` fragments IP packets into bounded QUIC datagrams and safely reassembles them.
- TLS 1.3 provides encryption, while mutual TLS binds VPN clients to explicit identities, addresses, access rules, and resource quotas.

On Linux, privileged network configuration is separated from the long-running transport process. A short-lived root helper creates routes, TUN devices, forwarding rules, and optional NAT. The data process then runs without root privileges, without `CAP_NET_ADMIN`, and with `NoNewPrivileges` enabled.

We also built a reproducible test environment using isolated Linux network namespaces and `tc netem`. Tests use fixed network seeds, reset queues between competitors, retain failed runs, and preserve raw benchmark evidence. The main measurements include:

$$
T_{\text{gap}}=\max_i(t_i-t_{i-1}),
$$

where $T_{\text{gap}}$ measures the longest interruption between correctly received records,

$$
G=\frac{8B_{\text{useful}}}{\Delta t},
$$

where $G$ is useful goodput, and

$$
\rho=\frac{B_{\text{wire}}}{B_{\text{application}}},
$$

which prevents apparent reliability improvements from hiding excessive wire overhead.

In the locked experiments, FlowWeave preserved the original connection and complete data through path blackholes with sub-second recovery gaps. It reached approximately $26.58$ and $27.51\ \text{Mbit/s}$ in the balanced and heterogeneous aggregation scenarios. Its real-time experiment achieved a median P95 latency of about $23.28\ \text{ms}$, compared with $29.66\ \text{ms}$ for the strongest tested Hysteria configuration.

The Linux MPTCP comparison was equally important: MPTCP slightly exceeded FlowWeave in balanced aggregation and nearly matched it in the heterogeneous case, while FlowWeave performed substantially better during complete path blackholes. This showed that FlowWeave’s clearest advantage is bounded recovery, not universal throughput superiority.

## Challenges We Faced

The hardest problem was discovering that multipath transport is not only a data-scheduling problem—it is also a feedback-routing problem.

Early versions successfully moved data onto a backup path, but acknowledgements could still return through the failed path. In some cases, a healthy backup path was even considered idle because its traffic was acknowledged elsewhere. Fixing this required same-path acknowledgement behavior, ACK-progress-based recovery timers, bounded cross-path feedback escape, and careful reinjection of only the data needed to unblock delivery.

Another challenge was balancing competing goals. Aggressive duplication can improve reliability but waste bandwidth. Sending everything down the lowest-latency path can leave available capacity unused. Maximizing throughput can also make tail latency worse. Every added mechanism therefore had to demonstrate measurable value under a predeclared test contract.

Building a safe IP tunnel introduced a different class of problems: MTU limits, fragmentation, overlapping fragments, spoofed source addresses, unbounded reassembly, reconnect generations, and cleanup after crashes. We addressed these with strict parsing, bounded queues and memory budgets, per-identity policies, atomic session replacement, and transactional network cleanup.

Finally, creating a fair benchmark was almost as difficult as creating the transport. Short tests produced attractive but misleading results. Fixed seeds did not eliminate congestion-control and scheduler variance. We learned to use multiple runs, medians, worst cases, immutable raw results, and thresholds written before experiments began.

## What We Learned

FlowWeave taught us that resilience is an end-to-end property. A second path is not useful unless data, acknowledgements, congestion state, identity, routing, and process lifecycle can all survive failure together.

We also learned that failed experiments are valuable when their evidence is preserved. Several promising recovery strategies passed short screenings but failed longer bidirectional tests. Those failures revealed deeper protocol issues that a favorable single benchmark would have hidden.

Most importantly, we learned to treat complexity as something that must be earned. A new scheduler, timer, redundancy mechanism, or privileged component stays only when it produces a repeatable improvement without weakening security or operational safety.

## What’s Next

The client now uses unprivileged Linux network events to shorten reconnect backoff while retaining timer fallback and full TLS/session revalidation. The next steps are dedicated in-place path and NAT-rebinding tests, online client certificate rotation, DNS integration, multi-client stress testing, real-host installation validation, and longer trials across genuinely independent network providers.

The long-term vision remains simple: make several imperfect networks feel like one resilient connection.
