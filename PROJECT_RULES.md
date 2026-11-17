# PROJECT_RULES.md — t3Bridge Architecture & Engineering Guidelines

> **Project Name:** `t3Bridge`  
> **Type:** Universal P2P Business Application Bridge & Mesh Network  
> **Primary Target:** High-performance, zero-latency LAN-over-WAN bridging for Desktop Business & Accounting Software (Marg ERP, Tally Prime, Busy ERP, Custom SMB & RDP workloads).  
> **Core Tech Stack:** Rust (Modular Cargo Workspace) + Tauri v2 (Frontend Desktop GUI).

---

## 1. Architectural Principles & Boundaries

Every developer and AI agent working on `t3Bridge` MUST strictly adhere to **Clean Architecture / Hexagonal Architecture**:

### Rule 1.1: The Dependency Rule
* Dependencies must point **strictly inwards**:
  $$\text{UI / Drivers} \longrightarrow \text{Adapters} \longrightarrow \text{Application Use Cases} \longrightarrow \text{Core Domain}$$
* **Core Domain (`crates/domain`)** must remain 100% pure:
  * NO operating system APIs (`windows-rs`, `winapi`).
  * NO network driver or socket dependencies (`wintun`, `tokio-tungstenite`).
  * ONLY pure entities, value objects, domain errors, and state machines.

### Rule 1.2: Port & Adapter Decoupling
* Any external interaction (Windows drive mounting, firewall manipulation, Wintun adapter initialization, cryptographic verification, file system storage) MUST be declared as a **Rust Trait (Port)** in the `application` layer.
* Use Cases must interact with traits via `Arc<dyn Trait>` or generic bounds, NEVER with concrete structs from `adapters`.

### Rule 1.3: Presentation Isolation (Tauri UI)
* The UI layer (`src-tauri` and web frontend) is strictly for presentation, status visualization, and dispatching user intents.
* NO business logic, encryption, or direct Windows API calls inside UI components or Tauri commands. Tauri commands must simply call the corresponding Application Use Case.

---

## 2. Universal Business Application Rule (Zero Hardcoding)

`t3Bridge` is NOT limited to a single ERP. It is a universal bridge for all business software:

* **Rule 2.1:** **NO hardcoded share names or paths** (e.g., NEVER hardcode `\\SERVER\MargERP` or `margwin.exe`).
* **Rule 2.2:** Support configurable **`AppProfile`** abstractions:
  * Application Name (e.g. "Marg ERP", "Tally Prime", "Busy Accounting", "Generic File Share").
  * Target SMB Share name or local port forwarding rules.
  * Executable launcher path (optional client helper).
  * Auto-mount drive letter selection (e.g., 'Z:', 'Y:', or auto-assign available).

---

## 3. Superpowers Test-Driven Development (TDD) Mandate

Following the `obra/superpowers` engineering standard:

* **Rule 3.1: Spec-First & Red-Green-Refactor:**
  * Before implementing any Use Case or Domain feature, define the trait and write the failing unit test with `mockall` (**RED**).
  * Write the minimal code to satisfy the test (**GREEN**).
  * Optimize, clean, and verify type safety (**REFACTOR**).
* **Rule 3.2: 100% Mockability:**
  * Since real Windows drivers (`wintun.dll`) and network sockets cannot run in standard CI or offline test runs, every port must be mockable with `mockall`.
  * All application tests must run and pass offline via `cargo test --workspace`.

---

## 4. State Safety & Compile-Time Guarantees

* **Rule 4.1: Type-State Pattern Enforcement:**
  * Connection transitions must be compile-time guaranteed using Rust's Type-State pattern:
    $$\text{Disconnected} \longrightarrow \text{Licensed} \longrightarrow \text{TunnelActive} \longrightarrow \text{DriveMounted}$$
  * A developer must NOT be able to call `mount_drive()` or access shares if the state is not in `TunnelActive`.

---

## 5. Commercial Licensing & Security Invariants

* **Rule 5.1: Hardware Binding (HWID):**
  * Node activation must be cryptographically tied to the machine's Hardware ID (CPU, Motherboard, Machine GUID hash).
* **Rule 5.2: Asymmetric Cryptography (Ed25519):**
  * Licenses must be signed by the author's private key and verified using the embedded public key.
  * Client binaries must NEVER contain private signing keys.
* **Rule 5.3: Safe Disconnects (Anti-Corruption):**
  * On sudden network loss or app exit, the system must cleanly flush I/O, unmount network drives, and release SMB locks to protect user database files.
