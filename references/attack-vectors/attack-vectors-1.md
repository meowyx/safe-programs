# Attack Vectors Reference - Account Validation & Authorization (1/4)

> Part 1 of 5 · Vectors 1–25 of 105 total
> Covers: signer checks, ownership, discriminators, account constraints, reinitialization, account validation chains

---

## V1 - Missing Signer Check

**Detect:** `AccountInfo<'info>` or `UncheckedAccount<'info>` for authority/admin accounts instead of `Signer<'info>`. In native: `next_account_info` on authority without `if !account.is_signer` check.

**Vulnerable:**
```rust
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,  // NOT Signer - anyone can pass any pubkey
}
```

**Exploit:** Attacker passes the vault owner's pubkey as `authority` without signing. Drains vault.

**Secure:**
```rust
pub authority: Signer<'info>,  // Anchor enforces is_signer
// Native:
if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }
```

---

## V2 - Missing Owner Check on Deserialized Account

**Detect:** `try_from_slice()` / `unpack()` / `BorshDeserialize` on account data without prior `account.owner == expected_program_id` check. In Anchor: `AccountInfo<'info>` with `/// CHECK:` used instead of `Account<'info, T>`.

**Vulnerable:**
```rust
let vault: Vault = Vault::try_from_slice(&vault_account.data.borrow())?;
// No check: vault_account.owner == program_id
// Attacker creates fake account with identical layout, owned by their program
```

**Exploit:** Attacker crafts account with spoofed balance/authority fields. Program trusts the data.

**Secure:**
```rust
if vault_account.owner != program_id { return Err(ProgramError::IncorrectProgramId); }
// Anchor: Account<'info, Vault> auto-checks owner
```

---

## V3 - Type Cosplay - Missing Discriminator

**Detect:** In native programs: `BorshDeserialize` structs without an 8-byte discriminant field at offset 0. `try_from_slice()` without discriminator check. In Anchor: `AccountLoader<'info, T>` (zero-copy accounts) - does NOT auto-check discriminators unlike `Account<'info, T>`.

**Vulnerable:**
```rust
#[derive(BorshDeserialize)]
pub struct User { authority: Pubkey, balance: u64 }
// No discriminant field - AdminConfig has same layout, can be substituted

// Anchor zero-copy: AccountLoader also skips discriminator check!
#[account(mut)]
pub user: AccountLoader<'info, User>,  // type cosplay possible
```

**Exploit:** Attacker passes `AdminConfig` account where `User` is expected. Data layouts overlap - attacker's pubkey becomes the "authority." With `AccountLoader`, zero-copy deserialization bypasses the discriminator check that `Account<'info, T>` performs automatically.

**Secure:**
```rust
pub struct User { discriminant: [u8; 8], authority: Pubkey, balance: u64 }
// Anchor: #[account] macro auto-generates discriminator
// For AccountLoader: use Account<'info, T> when possible, or add manual discriminator check
```

---

## V4 - Reinitialization Attack

**Detect:** `init` instructions without `is_initialized` flag check (native). `init_if_needed` without post-init state validation (Anchor). Missing discriminator check before writing initialization data.

**Vulnerable:**
```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    ctx.accounts.config.authority = ctx.accounts.signer.key();  // overwrites existing authority
    Ok(())
}
// No check whether config was already initialized
```

**Exploit:** Attacker calls `initialize` again to overwrite authority with their own key.

**Secure:**
```rust
// Native: if config.is_initialized { return Err(AlreadyInitialized); }
// Anchor: #[account(init, ...)] prevents reinit via discriminator check
```

---

## V5 - init_if_needed Without State Validation

**Detect:** `init_if_needed` in Anchor `#[account(...)]` constraints without subsequent validation of existing state fields when account already exists.

**Vulnerable:**
```rust
#[account(init_if_needed, payer = user, space = 8 + UserState::INIT_SPACE,
          seeds = [b"user", pool.key().as_ref()], bump)]
pub user_state: Account<'info, UserState>,
// If account exists, no check that user_state.owner == user.key()
```

**Exploit:** Attacker pre-creates the PDA with their own authority before the legitimate user. When legitimate user calls, account already exists with attacker's authority.

**Secure:**
```rust
// Either use `init` (fails if exists) or validate existing state:
if user_state.is_initialized {
    require!(user_state.owner == user.key(), Unauthorized);
}
```

---

## V6 - Missing has_one / Data Mismatch

**Detect:** `Account<'info, T>` with `#[account(mut)]` but no `has_one`, `constraint`, or manual field comparison linking it to other accounts in the instruction.

**Vulnerable:**
```rust
#[account(mut)]
pub vault: Account<'info, Vault>,
pub authority: Signer<'info>,
// No check: vault.authority == authority.key()
// Attacker passes their own vault
```

**Exploit:** Attacker passes a vault they control instead of the victim's vault.

**Secure:**
```rust
#[account(mut, has_one = authority)]
pub vault: Account<'info, Vault>,
```

---

## V7 - Missing Writable Annotation

**Detect:** Account modified in instruction handler but missing `#[account(mut)]` in Anchor. State changes are silently discarded at end of instruction.

**Vulnerable:**
```rust
#[account]  // missing `mut`
pub user_state: Account<'info, UserState>,
// In handler: user_state.balance += amount;  // change silently discarded
```

**Exploit:** State updates never persist. Can cause accounting desync - user deposited but balance unchanged.

**Secure:**
```rust
#[account(mut)]
pub user_state: Account<'info, UserState>,
```

---

## V8 - UncheckedAccount Without Manual Validation

**Detect:** `UncheckedAccount<'info>` or `AccountInfo<'info>` with `/// CHECK:` comment but no actual validation code (owner check, key comparison, PDA derivation).

**Vulnerable:**
```rust
/// CHECK: trust me bro
pub oracle: UncheckedAccount<'info>,
// No owner check, no key comparison - attacker can pass any account
```

**Exploit:** Attacker passes fake oracle account with manipulated price data.

**Secure:**
```rust
/// CHECK: Validated below
pub oracle: UncheckedAccount<'info>,
// In handler: require!(*oracle.owner == PYTH_PROGRAM_ID, InvalidOracle);
```

---

## V9 - remaining_accounts Without Validation

**Detect:** `ctx.remaining_accounts.iter()` without owner, discriminator, or key checks inside the loop.

**Vulnerable:**
```rust
for account in ctx.remaining_accounts.iter() {
    let data = account.try_borrow_data()?;
    process_account_data(&data)?;  // no owner/type validation
}
```

**Exploit:** Attacker injects malicious accounts into remaining_accounts - bypass Anchor's constraint system.

**Secure:**
```rust
for account in ctx.remaining_accounts.iter() {
    require!(account.owner == &crate::ID, InvalidOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 8 && data[..8] == UserState::DISCRIMINATOR, InvalidType);
}
```

---

## V10 - Improper Account Closing - Revival Attack

**Detect:** Account closure via `**account.lamports.borrow_mut() = 0` without zeroing data bytes or writing `CLOSED_ACCOUNT_DISCRIMINATOR`. Missing Anchor `close = recipient` constraint.

**Vulnerable:**
```rust
**dest.lamports.borrow_mut() = dest.lamports().checked_add(source.lamports()).unwrap();
**source.lamports.borrow_mut() = 0;
// Data NOT zeroed - account can be revived by transferring lamports back in same tx
```

**Exploit:** Within same transaction: close account → transfer 1 lamport back → reuse with stale data.

**Secure:**
```rust
// Anchor: #[account(mut, close = recipient)]
// Native: zero data + drain lamports + assign to System Program
let mut data = account.try_borrow_mut_data()?;
for byte in data.deref_mut().iter_mut() { *byte = 0; }
data[..8].copy_from_slice(&CLOSED_ACCOUNT_DISCRIMINATOR);
```

---

## V11 - Operations on Closed Accounts in Same Transaction

**Detect:** Instructions that read/write accounts without checking `lamports() > 0`. Account closed in instruction N, accessed in instruction N+1 within same transaction.

**Vulnerable:**
```rust
let data = ctx.accounts.user_data.load()?;  // reads closed account - data is stale/zeroed
```

**Secure:**
```rust
require!(**ctx.accounts.user_data.to_account_info().lamports.borrow() > 0, AccountClosed);
```

---

## V12 - Duplicate Mutable Accounts

**Detect:** Two or more `#[account(mut)]` fields of the same `Account<'info, T>` type without `constraint = a.key() != b.key()`.

**Vulnerable:**
```rust
#[account(mut)] pub from: Account<'info, TokenAccount>,
#[account(mut)] pub to: Account<'info, TokenAccount>,
// from == to: self-transfer doubles balance
```

**Exploit:** Pass same account for `from` and `to`. Last serialization wins - balance doubled.

**Secure:**
```rust
#[account(mut, constraint = from.key() != to.key() @ SameAccount)]
```

---

## V13 - Missing Token Account Mint Validation

**Detect:** Token account used in transfer/CPI without `token::mint = expected_mint` constraint or manual `mint` field comparison.

**Vulnerable:**
```rust
#[account(mut)]
pub user_token: Account<'info, TokenAccount>,
// No check: user_token.mint == expected_mint.key()
```

**Exploit:** Attacker passes token account for a worthless mint, receives valuable tokens.

**Secure:**
```rust
#[account(mut, token::mint = expected_mint)]
```

---

## V14 - Missing Token Account Authority Validation

**Detect:** Token account `owner` field not validated against expected authority. Missing `token::authority = expected` or `has_one = authority`.

**Vulnerable:**
```rust
#[account(mut)]
pub vault_token: Account<'info, TokenAccount>,
// No check: vault_token.owner == vault_pda.key()
// Attacker passes their own token account
```

**Secure:**
```rust
#[account(mut, token::authority = vault_pda)]
```

---

## V15 - Sysvar Account Spoofing

**Detect:** Sysvar passed as `AccountInfo<'info>` without address validation. Use of `load_instruction_at()` (unchecked) instead of `load_instruction_at_checked()`. Absence of `Sysvar<'info, Clock>` type.

**Vulnerable:**
```rust
let instructions_sysvar = next_account_info(accounts_iter)?;
let ix = load_instruction_at(0, instructions_sysvar)?;  // unchecked - no address validation!
```

**Exploit:** **Wormhole ($320M)** - attacker passed fake Instructions sysvar, bypassed guardian signature verification.

**Secure:**
```rust
// Use syscall (no account needed): Clock::get()?
// Or validate address: require!(*sysvar.key == sysvar::instructions::ID);
// Or Anchor: Sysvar<'info, Clock>
```

---

## V16 - Instruction Introspection Bypass

**Detect:** `load_instruction_at_checked(0, ...)` with hardcoded absolute index. Same instruction at index 0 validates multiple program invocations.

**Vulnerable:**
```rust
let prev_ix = load_instruction_at_checked(0, &sysvar)?;  // absolute index 0
require!(prev_ix.program_id == ed25519_program::ID);
// Attacker puts benign Ed25519 at index 0, reuses it to validate malicious calls at index 1, 2, ...
```

**Secure:**
```rust
let current_idx = load_current_index_checked(&sysvar)?;
let prev_ix = load_instruction_at_checked((current_idx - 1) as usize, &sysvar)?;
// Relative indexing - each instruction validates its own predecessor
```

---

## V17 - System / Token Program Confusion

**Detect:** `AccountInfo<'info>` used for program accounts instead of `Program<'info, Token>` or `Program<'info, System>`. Missing `require_keys_eq!` against known program IDs.

**Vulnerable:**
```rust
pub token_program: AccountInfo<'info>,  // not validated
// invoke(&instruction, &[..., token_program.clone()])?;
```

**Exploit:** Attacker passes malicious program - returns success without performing transfer.

**Secure:**
```rust
pub token_program: Program<'info, Token>,  // auto-validates program ID
```

---

## V18 - Missing Config Account Update Constraints

**Detect:** Config/settings update instructions with `Signer<'info>` but no `constraint` linking signer to stored admin. No range validation on numeric params.

**Vulnerable:**
```rust
pub struct UpdateConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,  // any signer can call - no has_one!
}
```

**Secure:**
```rust
#[account(mut, has_one = admin)]
pub config: Account<'info, Config>,
pub admin: Signer<'info>,
// Plus: require!(new_fee_bps <= 10_000, FeeTooHigh);
```

---

## V19 - Predictable PDA Initialization

**Detect:** `#[account(init, ...)]` with PDA seeds that don't include the payer's/authority's key. Seeds derivable by anyone - attacker can pre-create the PDA.

**Vulnerable:**
```rust
#[account(init, seeds = [b"config", pool.key().as_ref()], bump, payer = user)]
pub config: Account<'info, Config>,
// Anyone can derive this PDA and initialize it first via Jito bundle
```

**Exploit:** **Pump Science (H-01)** - attacker front-ran `lock_pool` by pre-creating the lock_escrow PDA with predictable seeds. Legitimate migration blocked.

**Secure:**
```rust
seeds = [b"config", pool.key().as_ref(), authority.key().as_ref()]
// Or: validate caller is upgrade authority
```

---

## V20 - Missing Account Validation Chain

**Detect:** `Account<'info, T>` without `seeds`/`bump` or `address` constraint used as a trust anchor for other account constraints (e.g., `has_one`, `constraint`).

**Vulnerable:**
```rust
pub config: Account<'info, Config>,          // UNCONSTRAINED - attacker provides fake
#[account(constraint = vault.config == config.key())]
pub vault: Account<'info, Vault>,            // meaningless - validates against fake config
```

**Exploit:** **Cashio ($48M)** - fake `bank` account passed, all downstream constraints validated against it. Attacker minted unlimited stablecoins with worthless collateral.

**Secure:**
```rust
#[account(seeds = [b"config"], bump = config.bump)]  // PDA-anchored root of trust
pub config: Account<'info, Config>,
#[account(constraint = vault.config == config.key())]
pub vault: Account<'info, Vault>,
```

---

## V21 - Account Space Miscalculation

**Detect:** `space = ` in `#[account(init)]` without `8 +` (missing discriminator). Wrong sizes for `Pubkey` (32), `u64` (8), `bool` (1), `Vec<T>` (4 + len * T), `String` (4 + len), `Option<T>` (1 + T).

**Vulnerable:**
```rust
#[account(init, space = std::mem::size_of::<UserState>(), payer = user)]
// Missing 8-byte discriminator - account too small, deserialization fails
```

**Exploit:** Undersized accounts cause runtime deserialization errors → DoS. From **Mintify audit**: wrong `LEN` calculations (off by bytes).

**Secure:**
```rust
#[account(init, space = 8 + UserState::INIT_SPACE, payer = user)]
// Or: #[derive(InitSpace)] on the struct
```

---

## V22 - Ed25519 Signature Verification Bypass

**Detect:** `ed25519_program::ID` check without validating signing pubkey, message content, or signature bytes. Missing nonce for replay prevention. Absolute instruction index.

**Vulnerable:**
```rust
let ix = load_instruction_at_checked(0, &sysvar)?;
require!(ix.program_id == ed25519_program::ID);
// Doesn't validate WHICH pubkey signed or WHAT message was signed
```

**Exploit:** Attacker reuses a legitimate Ed25519 verification from another context. No replay protection - same signature works across transactions.

**Secure:**
```rust
let sig_data = Ed25519InstructionData::unpack(&ix.data)?;
require!(sig_data.public_key == expected_signer.to_bytes());
require!(sig_data.message == expected_message);
// Nonce: require!(!nonce_account.used); nonce_account.used = true;
```

---

## V23 - Unconstrained Mint Authority

**Detect:** Mint instruction without `mint::authority = expected` constraint. Token mint CPI without authority signer validation.

**Vulnerable:**
```rust
pub fn mint_tokens(ctx: Context<MintTokens>, amount: u64) -> Result<()> {
    token::mint_to(ctx.accounts.mint_ctx(), amount)?;
    // No check that caller is authorized to mint
}
```

**Exploit:** Anyone calls mint instruction → infinite supply inflation.

**Secure:**
```rust
#[account(constraint = mint.mint_authority == COption::Some(authority.key()))]
pub mint: Account<'info, Mint>,
pub authority: Signer<'info>,
```

---

## V24 - Insecure Initialization - No Upgrade Authority Check

**Detect:** Global `initialize` instruction callable by any signer without checking the program's upgrade authority.

**Vulnerable:**
```rust
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    ctx.accounts.global.authority = ctx.accounts.signer.key();  // any signer becomes authority
}
```

**Exploit:** **Lombard audit (M2), Onre audit (L2)** - attacker front-runs deployment, calls `initialize` first, becomes protocol admin.

**Secure:**
```rust
#[account(constraint = program.programdata_address()? == Some(program_data.key()))]
pub program: Program<'info, MyProgram>,
#[account(constraint = program_data.upgrade_authority_address == Some(authority.key()))]
pub program_data: Account<'info, ProgramData>,
```

---

## V25 - Missing State Update in Mutation Function

**Detect:** State update functions (like `update_settings`) that don't assign all fields from input params. Copy-paste errors where one field is simply omitted.

**Vulnerable:**
```rust
pub fn update_settings(&mut self, params: SettingsInput) {
    self.fee_rate = params.fee_rate;
    self.admin = params.admin;
    // MISSING: self.migration_allocation = params.migration_allocation;
    self.whitelist = params.whitelist;
}
```

**Exploit:** **Pump Science (H-02)** - `migration_token_allocation` never updatable after initialization. Admin believes they changed it but the value stays the same.

**Secure:** Verify every field in the input struct has a corresponding assignment. Write tests that round-trip all settings.
