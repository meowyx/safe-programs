# safe-programs

Solana security skill for writing, auditing and brainstorming solana programs.

Three modes, one ruleset.

- **brainstorm** - design-time thinking partner. Surfaces architectural risks
  before code exists. Produces `design-notes.md` with captured decisions, open
  questions, and framework/testing choices.
- **build** - scaffold a new Solana program (Anchor, Native Rust, or Pinocchio)
  with tests (LiteSVM or framework default) and a filled-out security
  checklist. Security baked in before the first line.
- **audit** - fan 8 parallel agents over an existing program, deduplicate,
  gate-check, produce a findings report. Optional 9th protocol agent in deep
  mode for DeFi.

Same rules underneath. Design decisions in brainstorm, enforcement in build,
hunting in audit. Natural flow is brainstorm → build → audit, but you can enter
at any mode.

---

## What it enforces

Rules are derived from real audit findings, not generic best practices.

- account and identity validation (signer, owner, discriminator, reinit)
- PDA safety (canonical bumps, sharing, seed collision, purpose isolation)
- arithmetic (checked math, multiply-before-divide, slippage on net not gross)
- duplicate mutable account attacks
- full CPI trust surface (arbitrary CPI, stale reload, signer pass-through,
  SOL balance delta, post-CPI ownership, invoke vs invoke_signed)
- account lifecycle (rent, anti-revival close, sysvar verification)
- Token-2022 (transfer_checked, extension validation at init,
  fee-on-transfer delta accounting, mint space after all extensions declared)
- reward accounting (settle before shrinking, reward_debt on every payout,
  no retroactive rate, dead share price, inflation attack, rewards from
  principal)
- vault architecture (withdrawal paths, backing invariants, spendable vs
  reserved)
- slippage and fee ordering (net not gross, fee base matches executed amount,
  fee can't block payout)
- AMM and bonding-curve (completion-threshold capping, post-cap slippage
  recheck, terminal-state solvency, reserve layer alignment)
- config management (every write-path validation, tri-state patch semantics,
  cross-field invariants, atomic commit)
- admin key security (two-step rotation, timelock for 🔴 critical)
- BPF runtime (4096-byte stack frame DoS, Box mitigation)
- input validation and metadata hygiene (non-empty, length bounds, URI
  scheme allowlists)
- panic safety (no unwrap/expect on user-controlled paths, always typed errors)
- instruction introspection and self-CPI patterns (sysvar verification,
  transfer hook reentry, checks-effects-interactions, flash-loan detection
  limits, top-level vs CPI guards)

## Output

### brainstorm mode

- `design-notes.md` - captured design decisions with alternatives considered,
  shared-base section references, and reasoning
- open questions list (decisions not yet made)
- framework and testing choices with justification
- known risks flagged at design time
- hand-off to build mode when ready, with decisions pre-filled

### build mode

- full project scaffold (`Anchor.toml` / `Cargo.toml` / folders), ready to
  `anchor build` or `cargo build-sbf`
- `lib.rs` - complete, compilable, inline security comments
- test file - LiteSVM or framework-default. Happy path implemented. Security
  edge cases stubbed with `TODO` + why.
- `security-checklist.md` - every rule applied, every assumption, every known
  limitation, risk level at the top

### audit mode

- per-agent findings with confidence scores
- deduplicated, gate-validated, fix-verified
- composite chains where multiple findings compound
- structured per `references/report-formatting.md`

## Structure

```
safe-programs/
├── SKILL.md                     # orchestrator, three modes
├── references/
│   ├── shared-base.md           # rules for every Solana program
│   ├── anchor.md                # Anchor-specific
│   ├── native-rust.md           # Native Rust-specific
│   ├── pinocchio.md             # Pinocchio-specific
│   ├── litesvm.md               # LiteSVM test patterns
│   ├── judging.md               # 4-gate validation for audit mode
│   ├── report-formatting.md     # audit mode output format
│   ├── attack-vectors/          # 5 files, vector-scan agent's input
│   └── hacking-agents/          # per-agent instructions + shared rules
├── examples/
│   └── nft-whitelist-mint/      # Anchor, 🔴 critical, quality benchmark
├── README.md
└── VERSION
```

## Install

Drop the directory into `~/.claude/skills/safe-programs/` or symlink it there.
Claude Code picks up skills automatically on next session start.

### Triggers

**brainstorm:**
- "thinking about building..."
- "how would I design..."
- "should I use Anchor or Pinocchio for X"
- "what should I consider for Y"
- "brainstorm a solana program"
- "talk me through designing..."

**build:**
- "write a solana program that..."
- "scaffold a solana program"
- "build an anchor program for..."
- "create a native rust solana program..."
- "help me write a program that does X on solana"

**audit:**
- "audit this"
- "review for security"
- "check this program"
- "find the bugs"
- `/safe-programs`
- `/safe-programs --deep`
- `/safe-programs programs/vault/src/lib.rs`
- `/safe-programs --file-output`

## Credits

I started from two upstream skills, merged them into one base, and I'm layering my own rules and coverage on top.

- [safe-solana-builder](https://github.com/Frankcastleauditor/safe-solana-builder) by Frank Castle - the builder side. Shared-base rules, framework refs (Anchor, Native Rust, Pinocchio), LiteSVM patterns, and the nft-whitelist-mint example started here.
- [solana-auditor-skills](https://github.com/sanbir/solana-auditor-skills) by sanbir, forked from [pashov/skills](https://github.com/pashov/skills) - the audit orchestration. Attack-vectors collection, 8 hacking agents, judging gates, and report format started here.

Both are worth checking out on their own. safe-programs merges them into a single skill sharing one ruleset, with the prose rewritten in my voice and new rules added over time.

## License

MIT.
