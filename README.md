# 🛡️ Gas Town Audit Suite

One-command setup for a hardened Ubuntu server with a complete web3 security audit toolkit.

Spins up a dedicated `conductor` user, locks down SSH, and installs seven security tools — everything you need to start auditing smart contracts, verifying protocols, and running static analysis on a fresh Ubuntu 22.04/24.04 VPS.

## What gets installed

| # | Tool | Purpose | Binary |
|---|------|---------|--------|
| 1 | [Claude Code](https://docs.anthropic.com/en/docs/claude-code/overview) | AI coding agent for auditing assistance | `claude` |
| 2 | [Gastown](https://github.com/steveyegge/gastown) | Multi-agent orchestrator for parallel Claude Code sessions | `gt` |
| 3 | [Slither](https://github.com/crytic/slither) | Solidity/Vyper static analysis (Trail of Bits) | `slither` |
| 4 | [Aderyn](https://github.com/Cyfrin/aderyn) | Rust-based Solidity static analyzer (Cyfrin) | `aderyn` |
| 5 | [Tamarin Prover](https://tamarin-prover.com/) | Formal verification of cryptographic protocols | `tamarin-prover` |
| 6 | [TLA+](https://github.com/tlaplus/tlaplus) | Formal specification & model checking for protocol logic | `tlc` `pcal` `tla-sany` `tla-repl` |
| 7 | [CodeQL](https://codeql.github.com/) | Semantic code analysis engine (GitHub) | `codeql` |

## Server hardening

The script also handles baseline security before installing anything:

- Creates a `conductor` user with sudo privileges
- Installs your SSH public key
- **Disables password-based SSH** (key-only authentication)
- **Disables root login**
- Backs up the original `sshd_config` before modifying

## Quick start

```bash
# On your fresh Ubuntu server (as root):
chmod +x setup-security-tools.sh
sudo ./setup-security-tools.sh
```

The script will interactively prompt you for:

1. A **password** for the `conductor` user (with confirmation)
2. Your **SSH public key** (paste the full `ssh-ed25519 AAAA...` or `ssh-rsa AAAA...` line)

After the script completes (~45–90 min depending on Tamarin build), **test your SSH key login in a new terminal before closing your current session**:

```bash
ssh conductor@YOUR_SERVER_IP
```

Then load your tools:

```bash
source ~/.bashrc
claude          # authenticate Claude Code on first run
```

## Verify installation

```bash
claude --version
gt --version
slither --version
aderyn --version
tamarin-prover --help
tlc -h
codeql version
```

## Requirements

- **OS:** Ubuntu 22.04 or 24.04 (tested on Linode, works on any amd64 VPS)
- **RAM:** 4 GB minimum, 8 GB+ recommended (Tamarin and TLC benefit from more memory)
- **Disk:** 10 GB+ free space
- **Auth:** Anthropic account (Pro, Max, or Console) for Claude Code

## What gets installed under the hood

The script installs these runtimes as dependencies — you don't need to pre-install anything:

- **Go** 1.23.6 (for Gastown)
- **Node.js** 22 LTS (for Gastown)
- **Python 3** + pip (for Slither)
- **Rust** via rustup (for Aderyn)
- **Homebrew/Linuxbrew** (for Tamarin Prover)
- **OpenJDK 17** (for TLA+)

## Tool selection rationale

This toolkit covers the full spectrum of web3 security work:

**Smart contract static analysis** — Slither and Aderyn catch different classes of Solidity vulnerabilities. Running both gives better coverage than either alone. Slither excels at data-flow analysis and has more detectors; Aderyn is faster and produces cleaner reports.

**Formal verification (protocol logic)** — TLA+ models state machines and concurrent behavior. Use it to verify DeFi protocol invariants, governance logic, cross-chain message ordering, and economic state transitions. Most critical web3 bugs are logic bugs, not crypto breaks.

**Formal verification (cryptographic protocols)** — Tamarin Prover verifies cryptographic protocol properties under a Dolev-Yao adversary. Use it when auditing custom bridge protocols, MPC signing schemes, or novel key exchange flows.

**Semantic code analysis** — CodeQL enables custom queries across entire codebases. Write QL queries to find project-specific vulnerability patterns that generic static analyzers miss.

**AI-assisted auditing** — Claude Code provides an interactive coding agent for reviewing code, explaining complex logic, drafting findings, and automating repetitive audit tasks. Gastown orchestrates multiple Claude Code sessions in parallel for larger codebases.

## Customization

**Don't need Tamarin?** Comment out section 5 in the script to save 30–60 minutes of build time. Most smart contract audits don't require cryptographic protocol verification.

**Want sudo to require a password?** Remove `NOPASSWD` from line 89 of the script:

```diff
- ${CONDUCTOR} ALL=(ALL) NOPASSWD: ALL
+ ${CONDUCTOR} ALL=(ALL) ALL
```

**Different solc version?** Edit the `solc-select install` / `solc-select use` lines in section 3.

## Project structure

```
.
├── README.md
├── setup-security-tools.sh    # main setup script
└── LICENSE
```

## License

MIT

## Contributing

PRs welcome. If you'd like to add a tool, follow the existing pattern: numbered section, install as the `conductor` user, add to the summary output.
