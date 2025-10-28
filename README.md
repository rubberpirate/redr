# Rust EDR - Linux Endpoint Detection and Response System

A production-grade, high-performance Endpoint Detection and Response (EDR) system built in Rust for Ubuntu 24.04 and other Linux distributions. This EDR provides real-time monitoring, policy-driven threat detection, automated response capabilities, and an interactive web UI for human-in-the-loop approval workflows.

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Web UI](#web-ui)

---

## 🎯 Features

### Core Monitoring Capabilities

1. **Process Monitoring** - Real-time process snapshots via `/proc` parsing; heuristic-based detection of suspicious execs (shell scripts, netcat, telnet, etc.)
2. **File System Monitoring** - inotify-based file watching with SHA-256 hashing; automatic quarantine of blacklisted files
3. **Network Monitoring** - Parse `/proc/net/tcp` for active TCP connections; block ports and IPs via nftables
4. **Policy Engine** - Server-side policy with whitelist/blacklist rules; agents poll for updates every 10 seconds
5. **Automated Response** - SIGSTOP suspicious processes for human approval; quarantine files; kill/resume processes; block IPs/ports
6. **Command & Control** - REST API for command queue; agents poll and execute actions (kill, quarantine, block_ip, block_port, resume)
7. **Web UI** - Single-page application with live websocket telemetry; tabs for Processes, Network, Files, Alerts
8. **Human-in-the-Loop** - Hold suspicious processes (SIGSTOP) until approved from UI; Mark Safe to whitelist patterns

### Key Capabilities

- **Total Control**: Kill, quarantine, resume processes; block network ports; move files to quarantine directory
- **Threat Detection**: Heuristic process detection + hash-based file blacklisting (VirusTotal optional for future integration)
- **Demo-Ready**: Works on two Ubuntu 24.04 VMs + host monitor; build once, deploy everywhere
- **Real EDR**: Not a toy project—includes response primitives, policy system, and command queue

## Quickstart

This repository contains a working EDR prototype in Rust.

- `edr/server` — HTTP server (warp) with REST API (telemetry, commands, policy, whitelist) and websocket; serves web UI
- `edr/agent` — endpoint agent that collects process/file/network telemetry, fetches policy, stops suspicious processes, and executes commands

See `INSTRUCTIONS.md` for a step-by-step demo using two Ubuntu 24.04 VMs and your main OS as the monitor. See `THEORY.md` for notes about design, limitations, and next steps.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│            Web UI (Browser)             │
│   Processes | Network | Files | Alerts  │
│   (Kill, Quarantine, Block, Approve)    │
└──────────────┬──────────────────────────┘
               │ websocket + REST
┌──────────────▼──────────────────────────┐
│          EDR Server (Monitor)           │
│    POST /telemetry, GET /commands,      │
│    POST /command, GET /policy,          │
│    POST /whitelist, /ws, static UI      │
│  ┌──────────────────────────┐          │
│  │  In-Memory Storage       │          │
│  │  (commands, policy,      │          │
│  │   telemetry broadcast)   │          │
│  └──────────────────────────┘          │
│  Logs: edr_server.log (NDJSON)         │
└──────────────┬──────────────────────────┘
               │ HTTP (polling)
┌──────────────▼──────────────────────────┐
│         EDR Agents (Endpoints)          │
│  ┌──────────────────────────┐          │
│  │  Telemetry Collectors    │          │
│  │  - Process (proc parse)  │          │
│  │  - File (notify + SHA256)│          │
│  │  - Network (proc/net/tcp)│          │
│  └──────────────────────────┘          │
│  ┌──────────────────────────┐          │
│  │  Policy Engine           │          │
│  │  - Fetch policy (10s)    │          │
│  │  - Whitelist / Blacklist │          │
│  │  - Held PIDs (SIGSTOP)   │          │
│  └──────────────────────────┘          │
│  ┌──────────────────────────┐          │
│  │  Command Executor        │          │
│  │  - kill, quarantine,     │          │
│  │    block_ip, block_port, │          │
│  │    resume                │          │
│  └──────────────────────────┘          │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│         Linux Kernel / OS               │
│   (proc, notify, kill, nft, rename)     │
└─────────────────────────────────────────┘
```

---

## 📦 Package Alternatives & Comparisons

### 1. CLI Framework

#### **clap** (Recommended)
- **Version**: 4.5+
- **Features**: Derive macros, automatic help generation, shell completions
- **Pros**: Most popular, excellent documentation, type-safe, great error messages
- **Cons**: Larger binary size, compile time
- **Use Case**: Complex CLI with subcommands and rich help text

#### **structopt** 
- **Status**: Merged into clap v3+
- **Legacy**: Use clap instead with derive feature

#### **argh**
- **Features**: Lightweight, minimal dependencies
- **Pros**: Fast compilation, small binary size
- **Cons**: Less features, smaller community
- **Use Case**: Simple CLIs where minimalism is priority

#### **pico-args**
- **Features**: Minimal argument parser
- **Pros**: Tiny (< 500 LOC), no dependencies, fast
- **Cons**: Manual parsing, no help generation
- **Use Case**: Extremely simple CLIs with performance constraints

---

### 2. Async Runtime

#### **tokio** (Recommended)
- **Version**: 1.37+
- **Features**: Multi-threaded, work-stealing scheduler, rich ecosystem
- **Pros**: Industry standard, best documentation, most crates support it
- **Cons**: Heavier runtime, more complex
- **Use Case**: Complex async I/O, network operations, concurrent monitoring

#### **async-std**
- **Features**: Standard library-like API
- **Pros**: Familiar API design, simpler mental model
- **Cons**: Smaller ecosystem, less adoption
- **Use Case**: When you prefer std-lib style APIs

#### **smol**
- **Features**: Minimal async runtime
- **Pros**: Lightweight, simple, composable
- **Cons**: Fewer built-in utilities, smaller ecosystem
- **Use Case**: Embedded systems or minimal deployments

#### **embassy** (for embedded)
- **Features**: Async runtime for embedded/no_std
- **Pros**: Efficient for resource-constrained environments
- **Cons**: Not suitable for standard Linux applications
- **Use Case**: IoT/embedded Linux devices

---

### 3. Logging & Tracing

#### **tracing** (Recommended)
- **Version**: 0.1+
- **Features**: Structured logging, async-aware, span-based tracing
- **Pros**: Modern, async-compatible, rich context, performance
- **Cons**: Steeper learning curve
- **Use Case**: Complex applications with async code, detailed diagnostics

#### **slog**
- **Features**: Structured logging, extensible
- **Pros**: Composable, type-safe, very flexible
- **Cons**: More verbose, requires manual drain setup
- **Use Case**: When you need custom log processing pipelines

#### **log** + **env_logger**
- **Features**: Simple logging facade
- **Pros**: Minimal, widely supported, easy to start
- **Cons**: No structured logging, limited context
- **Use Case**: Simple applications, quick prototypes

#### **fern**
- **Features**: Simple configuration, log routing
- **Pros**: Easy configuration DSL, multiple outputs
- **Cons**: Less powerful than tracing/slog
- **Use Case**: Mid-complexity apps needing log routing

---

### 4. File System Monitoring

#### **notify** (Recommended - Cross-platform)
- **Version**: 6.1+
- **Features**: Cross-platform, abstracted API, debouncing
- **Pros**: Works on multiple OS, easy API, automatic backend selection
- **Cons**: Abstraction overhead, may miss rapid events
- **Use Case**: Cross-platform apps, general file watching

#### **inotify** (Linux-specific, High Performance)
- **Version**: 0.10+
- **Features**: Direct Linux inotify API bindings
- **Pros**: Maximum performance, low-level control, no overhead
- **Cons**: Linux-only, requires manual buffer management
- **Use Case**: Linux-specific EDR needing maximum performance

#### **inotify-rs** (Alternative inotify binding)
- **Features**: Safe inotify wrapper
- **Pros**: More ergonomic than raw inotify
- **Cons**: Less control than pure inotify
- **Use Case**: Balance between performance and ergonomics

#### **fanotify** (via nix crate)
- **Features**: Hierarchical file monitoring, permissions checks
- **Pros**: Can monitor entire filesystems, pre-access hooks
- **Cons**: Requires CAP_SYS_ADMIN, complex API
- **Use Case**: Security applications needing filesystem-wide monitoring

---

### 5. Process Monitoring

#### **procfs** (Recommended)
- **Version**: 0.16+
- **Features**: Parse /proc filesystem, process info, system stats
- **Pros**: Direct kernel data, comprehensive, type-safe
- **Cons**: Linux-only, no automatic updates
- **Use Case**: Detailed process information, system statistics

#### **sysinfo**
- **Version**: 0.30+
- **Features**: Cross-platform system information
- **Pros**: Easy API, auto-refreshing, CPU/memory/disk/network stats
- **Cons**: Higher-level abstraction, may miss details
- **Use Case**: General system monitoring, cross-platform needs

#### **procinfo** (Alternative)
- **Features**: Lightweight /proc parser
- **Pros**: Minimal dependencies
- **Cons**: Less maintained, fewer features
- **Use Case**: Minimal proc parsing needs

#### **Custom netlink** (via nix)
- **Features**: Kernel netlink sockets, process events
- **Pros**: Real-time process events (PROC_EVENTS), no polling
- **Cons**: Complex API, requires root/capabilities
- **Use Case**: Real-time process creation/termination detection

---

### 6. Network Monitoring

#### **nix** (Recommended for low-level)
- **Version**: 0.28+
- **Features**: Unix system APIs, socket operations, netlink
- **Pros**: Low-level control, efficient, comprehensive
- **Cons**: Unsafe code needed, complex
- **Use Case**: Deep network monitoring, packet filtering

#### **socket2**
- **Features**: Cross-platform socket creation
- **Pros**: Type-safe, cross-platform
- **Cons**: Higher level, less Linux-specific features
- **Use Case**: Standard network operations

#### **pcap** / **libpnet**
- **Features**: Packet capture and analysis
- **Pros**: Full packet inspection, protocol parsing
- **Cons**: Requires elevated privileges, resource-intensive
- **Use Case**: Deep packet inspection, network forensics

#### **netstat (custom)**
- **Features**: Parse /proc/net/* for connections
- **Pros**: No special permissions, simple
- **Cons**: Polling-based, snapshot only
- **Use Case**: Periodic connection monitoring

#### **AF_PACKET** sockets (via libc)
- **Features**: Raw packet access
- **Pros**: Maximum control, kernel-level filtering
- **Cons**: Complex, requires root
- **Use Case**: Custom protocol monitoring, DPI

---

### 7. eBPF Support (Advanced Kernel Monitoring)

#### **aya** (Recommended - Pure Rust)
- **Version**: 0.12+
- **Features**: Pure Rust eBPF, no LLVM dependency
- **Pros**: Rust-first, safe, modern, no C toolchain needed
- **Cons**: Newer project, smaller ecosystem
- **Use Case**: Modern eBPF development in pure Rust

#### **libbpf-rs**
- **Features**: Rust bindings to libbpf
- **Pros**: Mature libbpf backend, CO-RE support
- **Cons**: Requires libbpf C library, LLVM toolchain
- **Use Case**: Production systems, leveraging existing eBPF

#### **redbpf**
- **Features**: Rust eBPF framework
- **Pros**: Comprehensive, well-documented
- **Cons**: Development slowed, compilation complexity
- **Use Case**: If aya doesn't meet needs

#### **Manual bpf syscalls** (via libc)
- **Features**: Direct kernel BPF syscalls
- **Pros**: Maximum control
- **Cons**: Extremely complex, unsafe
- **Use Case**: Custom requirements not met by frameworks

---

### 8. Configuration Management

#### **config** (Recommended)
- **Version**: 0.14+
- **Features**: Multiple formats (TOML, JSON, YAML), layered configs
- **Pros**: Flexible, environment variables, hierarchical
- **Cons**: More complex API
- **Use Case**: Production apps with complex configuration

#### **toml** + **serde**
- **Features**: TOML parsing/serialization
- **Pros**: Simple, human-readable format
- **Cons**: Manual file handling
- **Use Case**: Simple config files

#### **serde_yaml** + **serde**
- **Features**: YAML support
- **Pros**: Complex structures, widely used
- **Cons**: YAML complexity, parsing overhead
- **Use Case**: When YAML is preferred format

#### **figment**
- **Features**: Composable configuration library
- **Pros**: Type-safe, provider-based, flexible
- **Cons**: Less widely adopted
- **Use Case**: Complex configuration needs

---

### 9. Data Storage/Database

#### **sled** (Recommended for embedded DB)
- **Version**: 0.34+
- **Features**: Embedded key-value store, ACID
- **Pros**: Pure Rust, fast, zero-config, crash-safe
- **Cons**: Not for massive datasets, less mature
- **Use Case**: Event logs, local state, time-series data

#### **rusqlite** (SQLite wrapper)
- **Version**: 0.31+
- **Features**: SQL database, relational
- **Pros**: Mature, SQL queries, widely understood
- **Cons**: Relational overhead for simple logs
- **Use Case**: When SQL queries are needed

#### **rocksdb** (via rust-rocksdb)
- **Features**: High-performance key-value store
- **Pros**: Battle-tested, high throughput, compression
- **Cons**: C++ dependency, larger binary
- **Use Case**: High-volume event storage

#### **redb**
- **Features**: Pure Rust embedded database
- **Pros**: Simple, fast, pure Rust
- **Cons**: Newer, less proven
- **Use Case**: Alternative to sled

---

### 10. Error Handling

#### **anyhow** (Recommended for applications)
- **Version**: 1.0+
- **Features**: Easy error handling, context, backtraces
- **Pros**: Simple, ergonomic, great for binaries
- **Cons**: Type erasure, not for libraries
- **Use Case**: Application code, CLI tools

#### **thiserror** (Recommended for libraries)
- **Version**: 1.0+
- **Features**: Derive Error trait, custom types
- **Pros**: Type-safe, great for libraries, clear errors
- **Cons**: More boilerplate than anyhow
- **Use Case**: Library code, public APIs

#### **eyre**
- **Features**: anyhow fork with better reports
- **Pros**: Beautiful error reports, hook system
- **Cons**: Slightly more complex
- **Use Case**: Better error diagnostics

#### **snafu**
- **Features**: Context-based error handling
- **Pros**: Ergonomic context, structured errors
- **Cons**: Learning curve, more explicit
- **Use Case**: Complex error scenarios

---

## 🚀 Implementation Approaches

### Approach 1: **eBPF-First Architecture** (Recommended for Production)

**Description**: Leverage eBPF for kernel-level monitoring with minimal overhead.

**Components**:
- **aya** for eBPF programs (kprobes, tracepoints, XDP)
- **Ring buffers** for efficient event transport
- **User-space agent** for event processing

**Advantages**:
- Minimal performance impact
- Kernel-level visibility
- Cannot be bypassed by userspace
- Real-time event capture

**Challenges**:
- Requires Linux 5.x+
- Complex debugging
- Needs kernel headers
- Privilege requirements

**Best For**: Production EDR with high-performance requirements

---

### Approach 2: **Hybrid Monitoring** (Balanced)

**Description**: Combine multiple Linux APIs for comprehensive coverage.

**Components**:
- **Process**: netlink PROC_EVENTS connector
- **File**: inotify + fanotify
- **Network**: AF_PACKET sockets + /proc/net parsing
- **Memory**: procfs + ptrace

**Advantages**:
- No eBPF dependency
- Works on older kernels (3.x+)
- Easier to debug
- Granular control per subsystem

**Challenges**:
- Higher overhead than eBPF
- Multiple monitoring threads
- Can miss rapid events
- More complex architecture

**Best For**: Broad compatibility, moderate performance needs

---

### Approach 3: **Polling-Based Monitoring** (Simplest)

**Description**: Regular polling of /proc, /sys, and /proc/net.

**Components**:
- **procfs** for process/memory state
- **sysinfo** for system metrics
- **notify** for file changes
- Periodic network connection dumps

**Advantages**:
- Extremely simple
- No special privileges required
- Easy to implement and debug
- Predictable resource usage

**Challenges**:
- Can miss transient events
- Higher latency
- Polling overhead
- Limited real-time capability

**Best For**: Development/testing, non-critical deployments

---

### Approach 4: **Audit Subsystem Integration**

**Description**: Use Linux Audit framework as event source.

**Components**:
- **audit** syscall monitoring
- **auditd** integration or direct netlink
- Parse audit logs in real-time
- Correlate events

**Advantages**:
- Kernel-level auditing
- Comprehensive syscall coverage
- Well-tested infrastructure
- Compliance-friendly

**Challenges**:
- Performance impact at scale
- Complex rule management
- Log volume can be massive
- Parsing complexity

**Best For**: Compliance-focused EDR, detailed forensics

---

### Approach 5: **Agent-Based with Central Collection** (Distributed)

**Description**: Lightweight agent on each host, central collector.

**Components**:
- Local monitoring agents (any approach above)
- Message queue (NATS, Kafka, RabbitMQ)
- Central detection engine
- Distributed storage

**Advantages**:
- Scalable to many endpoints
- Centralized threat detection
- Lower per-host processing
- Better correlation across hosts

**Challenges**:
- Network dependency
- More complex deployment
- Central point of failure
- Data transport overhead

**Best For**: Enterprise deployments, fleet management

---

### Approach 6: **Container-Aware Monitoring**

**Description**: Specialized monitoring for containerized environments.

**Components**:
- **containerd** / **docker** API integration
- **cgroup** monitoring
- **namespaces** tracking
- Container-specific eBPF programs

**Advantages**:
- Container context awareness
- Isolate per-container threats
- Track container lifecycle
- Modern infrastructure focus

**Challenges**:
- Container runtime dependency
- Additional complexity
- May miss host-level threats
- Runtime-specific implementation

**Best For**: Cloud-native environments, Kubernetes clusters

---

### Approach 7: **Machine Learning Enhanced** (Advanced)

**Description**: Add ML-based anomaly detection to behavioral rules.

**Components**:
- Baseline behavioral modeling
- Anomaly detection (autoencoders, isolation forest)
- Feature extraction from events
- Real-time scoring

**Advantages**:
- Detect unknown threats
- Reduced false positives over time
- Adaptive detection
- Zero-day capability

**Challenges**:
- Requires training data
- Resource intensive
- Model maintenance
- Complex implementation

**Best For**: Advanced threat detection, research projects

---

## 🔧 Installation

### Prerequisites

1. **Install Rust** (if not already installed):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

2. **Install system dependencies**:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev

# For eBPF support (optional)
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# Fedora/RHEL
sudo dnf install -y gcc pkg-config openssl-devel
sudo dnf install -y clang llvm libbpf-devel kernel-devel
```

### Build the Project

```bash
# Clone the repository
git clone https://github.com/yourusername/rust-edr.git
cd rust-edr

# Build in release mode
cargo build --release

# Build without eBPF support
cargo build --release --no-default-features

# Install globally
cargo install --path .
```

---

## 📖 Usage

### Basic Commands

```bash
# Start the EDR agent
sudo ./target/release/rust-edr start

# Monitor with specific modules
sudo ./target/release/rust-edr start --modules process,file,network

# Run in foreground with verbose logging
sudo ./target/release/rust-edr start --foreground --verbose

# Check status
sudo ./target/release/rust-edr status

# View recent alerts
sudo ./target/release/rust-edr alerts --recent 10

# Stop the agent
sudo ./target/release/rust-edr stop
```

### Configuration

Create a configuration file at `/etc/rust-edr/config.toml`:

```toml
[general]
log_level = "info"
data_dir = "/var/lib/rust-edr"
rules_dir = "/etc/rust-edr/rules"

[monitoring]
process_enabled = true
file_enabled = true
network_enabled = true
memory_enabled = false

[file_monitor]
watch_paths = [
    "/etc",
    "/usr/bin",
    "/usr/sbin",
    "/home",
]
exclude_paths = [
    "/home/*/.cache",
    "/tmp",
]

[network_monitor]
capture_interface = "any"
monitor_dns = true
monitor_http = true

[detection]
rule_engine = "behavioral"
threat_threshold = 7.0
auto_response = false

[response]
kill_process = false
isolate_network = false
alert_only = true

[storage]
backend = "sled"
retention_days = 30
max_size_gb = 10
```

---

## 🧪 Development

### Project Structure

```
rust-edr/
├── Cargo.toml
├── README.md
├── config/
│   └── default.toml
├── src/
│   ├── main.rs
│   ├── cli/
│   │   ├── mod.rs
│   │   └── commands.rs
│   ├── monitors/
│   │   ├── mod.rs
│   │   ├── process.rs
│   │   ├── file.rs
│   │   ├── network.rs
│   │   └── memory.rs
│   ├── detection/
│   │   ├── mod.rs
│   │   ├── engine.rs
│   │   ├── rules.rs
│   │   └── correlator.rs
│   ├── response/
│   │   ├── mod.rs
│   │   └── actions.rs
│   ├── storage/
│   │   ├── mod.rs
│   │   └── event_store.rs
│   └── utils/
│       ├── mod.rs
│       └── logger.rs
├── ebpf/ (optional)
│   └── programs/
└── tests/
    └── integration/
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with logging
cargo test -- --nocapture

# Run specific test
cargo test test_process_monitor

# Run integration tests (requires root)
sudo cargo test --test integration
```

---

## 🛡️ Security Considerations

- **Requires root privileges** for most monitoring operations
- **Secure the configuration** - contains sensitive rules
- **Log rotation** - implement to prevent disk exhaustion
- **Rate limiting** - prevent log flooding attacks
- **Input validation** - sanitize all external inputs
- **Audit the EDR** - who watches the watchers?

---

## 📊 Performance Guidelines

| Approach | CPU Overhead | Memory Usage | Latency | Completeness |
|----------|-------------|--------------|---------|--------------|
| eBPF | 1-3% | Low (MB) | < 1ms | High |
| Hybrid | 5-10% | Medium (10-50MB) | < 10ms | High |
| Polling | 2-5% | Low (MB) | 100ms-1s | Medium |
| Audit | 10-20% | High (100MB+) | < 10ms | Very High |

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🔗 Additional Resources

- [Linux Audit Documentation](https://man7.org/linux/man-pages/man7/audit.7.html)
- [eBPF Guide](https://ebpf.io/)
- [Rust Async Book](https://rust-lang.github.io/async-book/)
- [Linux Security Modules](https://www.kernel.org/doc/html/latest/admin-guide/LSM/)

---

## ⚠️ Disclaimer

This is a research/educational EDR system. For production environments, consider:
- Commercial EDR solutions (CrowdStrike, SentinelOne, etc.)
- Open-source alternatives (Wazuh, Osquery, etc.)
- Comprehensive testing and validation
- Professional security audit

---

**Status**: 🚧 Under Development

**Last Updated**: October 2025
