# t3Bridge Engineering & Clean Architecture Rules

You are working on `t3Bridge` — a universal P2P business application bridge written in Rust and Tauri.

## Core Mandates
1. **Clean Architecture Boundary:**
   - `crates/marg_domain` (Domain): Pure entities, value objects, and type-state pattern. ZERO dependencies on OS, Wintun, or network drivers.
   - `crates/marg_application` (Application): Use cases and Trait Ports. All system, tunnel, and license storage interactions must go through interfaces.
   - `crates/marg_adapters` (Adapters): Implementations of traits using `windows-rs`, `wintun`, `ed25519-dalek`, `tokio-tungstenite`.
   - `src-tauri` / Frontend (UI): Presentation only. No business logic in UI commands.

2. **Universal Business App Support (No ERP Hardcoding):**
   - NEVER hardcode paths or shares like `\MargERP` or `marg2014.exe`.
   - Always use `AppProfile` and user-configurable endpoints so `t3Bridge` seamlessly supports Marg ERP, Tally Prime, Busy Accounting, QuickBooks, and custom ERPs.

3. **Superpowers TDD Workflow:**
   - Every new use case must have automated tests using `mockall`.
   - Run `cargo test --workspace` to ensure all tests pass before completing any turn.

4. **Commercial Licensing & HWID:**
   - Node binding requires Hardware ID (`HardwareFingerprintPort`).
   - Digital signatures are verified using Ed25519 public key cryptography.
