# Attack Vectors Reference - PDA, CPI & Cross-Program Security (2/4)

> Part 2 of 5 · Vectors 26–50 of 105 total
> Covers: PDA derivation, seed security, CPI safety, invoke_signed, signer escalation, Token-2022 CPI, program validation

---

## V26 - Non-Canonical Bump Seed

**Detect:** `create_program_address` with user-supplied bump parameter instead of `find_program_address`. Bump accepted from instruction data or function args. Missing stored canonical bump reuse.

**Vulnerable:**
```rust
pub fn withdraw(ctx: Context<Withdraw>, bump: u8) -> Result<()> {
    let seeds = &[b"vault", user.key().as_ref(), &[bump]];  // user controls bump!
    let pda = Pubkey::create_program_address(seeds, ctx.program_id)?;
}
```

**Exploit:** Multiple valid bumps exist for same seeds. Attacker creates alternate PDAs, fragmenting state or bypassing PDA-based checks.

**Secure:**
```rust
// Anchor: seeds + bump auto-derives canonical bump
#[account(seeds = [b"vault", user.key().as_ref()], bump)]
// Native: let (pda, canonical_bump) = Pubkey::find_program_address(seeds, program_id);
// Store bump: vault.bump = canonical_bump;
```

---

## V27 - PDA Sharing - Missing User-Specific Seed

**Detect:** PDA `seeds` with only static strings (e.g., `seeds = [b"pool"]`) without user-specific or context-specific components. Same PDA reused across different authority domains.

**Vulnerable:**
```rust
#[account(seeds = [b"staking_pool_pda"], bump)]
pub pool: Account<'info, Pool>,
// All users share same PDA - one user's action affects everyone
```

**Exploit:** **Jet Protocol** - deposit notes PDA not derived from depositor pubkey. Any signed caller could burn another user's tokens.

**Secure:**
```rust
#[account(seeds = [b"user_pool", user.key().as_ref()], bump)]
```

---

## V28 - Seed Concatenation Collision

**Detect:** Variable-length user inputs (strings, byte slices) concatenated in PDA seeds without fixed-length encoding or delimiters.

**Vulnerable:**
```rust
seeds = [b"pool", token_name.as_bytes()]
// "poolABC" and "poolAB" + "C" could collide if seeds are concatenated
```

**Exploit:** `["AB", "C"]` and `["A", "BC"]` produce identical seed bytes → same PDA → cross-user state access.

**Secure:**
```rust
// Use fixed-length inputs (pubkeys are always 32 bytes)
seeds = [b"pool", mint_a.key().as_ref(), mint_b.key().as_ref()]
// Or hash variable-length inputs
```

---

## V29 - Seed Collision Across Account Types

**Detect:** Different PDA types (`vault`, `escrow`, `config`) using seeds without unique type prefixes. Same seed structure for different structs.

**Vulnerable:**
```rust
// Vault: seeds = [user.key().as_ref()]
// Escrow: seeds = [user.key().as_ref()]
// Same seeds → same PDA → type confusion
```

**Secure:**
```rust
seeds = [b"vault", user.key().as_ref()]   // unique prefix per type
seeds = [b"escrow", user.key().as_ref()]
```

---

## V30 - Arbitrary CPI - Unvalidated Program ID

**Detect:** `invoke()` or `invoke_signed()` where the target program is `AccountInfo<'info>` without `require_keys_eq!` against a known program ID. In Anchor: program account not typed as `Program<'info, T>`.

**Vulnerable:**
```rust
pub token_program: AccountInfo<'info>,  // anyone can pass any program
// ...
invoke(&transfer_ix, &[from, to, token_program.clone()])?;
```

**Exploit:** Attacker passes malicious program that returns success without transferring. **Sealevel attack #5**. Protocol believes transfer happened, updates state.

**Secure:**
```rust
pub token_program: Program<'info, Token>,  // auto-validates program ID
// Native: require!(*token_program.key == spl_token::ID);
```

---

## V31 - CPI Without Signer Seeds

**Detect:** `invoke()` used where PDA needs to sign (should be `invoke_signed()`). Or `invoke_signed()` with empty signer seeds `&[]`.

**Vulnerable:**
```rust
invoke(&transfer_ix, &[vault_pda, destination, token_program])?;  // vault_pda can't sign!
// Should be invoke_signed with vault PDA seeds
```

**Secure:**
```rust
let seeds = &[b"vault", &[vault.bump]];
invoke_signed(&transfer_ix, &[vault_pda, destination, token_program], &[seeds])?;
```

---

## V32 - CPI Signer Privilege Forwarding

**Detect:** User wallet (`Signer<'info>`) passed as a signer to CPI targeting an untrusted or upgradeable program. User's signing authority forwarded to third-party code.

**Vulnerable:**
```rust
let cpi_ctx = CpiContext::new(
    ctx.accounts.external_program.to_account_info(),  // untrusted program
    ExternalInstruction {
        user_wallet: ctx.accounts.user.to_account_info(),  // user's signer forwarded!
    },
);
```

**Exploit:** External program invokes System Program transfer from user's wallet, draining SOL. The user signed the outer transaction, so the signer privilege carries through CPI.

**Secure:**
```rust
// Use protocol PDA as CPI authority, never forward user signers to untrusted programs
let cpi_ctx = CpiContext::new_with_signer(
    ctx.accounts.external_program.to_account_info(),
    ExternalInstruction { authority: ctx.accounts.protocol_pda.to_account_info() },
    signer_seeds,
);
// Verify balances after CPI: require!(user.lamports() >= pre_balance - max_spend);
```

---

## V33 - Post-CPI Account Not Reloaded

**Detect:** Account field access after any `cpi::` call or `invoke`/`invoke_signed` without intervening `.reload()?`. Stale in-memory data used for decisions.

**Vulnerable:**
```rust
token::mint_to(cpi_ctx, amount)?;
msg!("Supply: {}", ctx.accounts.mint.supply);  // STALE - shows pre-mint value
// Decision based on stale balance can enable double-spend
```

**Exploit:** **Watt Protocol audit** - stale reward accumulator after CPI led to incorrect reward calculations.

**Secure:**
```rust
token::mint_to(cpi_ctx, amount)?;
ctx.accounts.mint.reload()?;  // refresh from on-chain data
msg!("Supply: {}", ctx.accounts.mint.supply);  // correct
```

---

## V34 - CPI Return Value Ignored

**Detect:** `invoke()` or CPI helper without `?` operator. `Result` from CPI not propagated.

**Vulnerable:**
```rust
spl_token::instruction::transfer(token_program.key, source.key, dest.key, authority.key, &[], amount);
// Return value ignored! Transfer may have failed.
```

**Exploit:** Transfer fails silently, state updated as if it succeeded. Balance accounting desyncs.

**Secure:**
```rust
invoke(&spl_token::instruction::transfer(...)?, &[source, dest, authority])?;
// Or Anchor: token::transfer(ctx, amount)?;
```

---

## V35 - invoke_signed with Incorrect Seeds

**Detect:** `invoke_signed` seeds that don't match the PDA derivation. Stored bump not used. Seeds in wrong order.

**Vulnerable:**
```rust
let seeds = &[b"vault", &[bump]];  // missing user.key() that was in init seeds!
invoke_signed(&ix, &accounts, &[seeds])?;  // PDA mismatch - CPI fails or signs wrong account
```

**Secure:**
```rust
let seeds = &[b"vault", user.key().as_ref(), &[vault.bump]];  // matches init derivation exactly
invoke_signed(&ix, &accounts, &[seeds])?;
```

---

## V36 - Missing Token Program ID Discrimination

**Detect:** Token operations using hardcoded `spl_token::ID` when Token-2022 mints may be involved. `anchor_spl::token::transfer` instead of `anchor_spl::token_interface::transfer_checked`.

**Vulnerable:**
```rust
anchor_spl::token::transfer(cpi_ctx, amount)?;  // hardcodes legacy Token program
// Fails on Token-2022 mints - DoS or fund loss
```

**Exploit:** **Tensor NFT Marketplace** - royalty payouts failed for Token-2022 mints because legacy `transfer` was hardcoded.

**Secure:**
```rust
anchor_spl::token_interface::transfer_checked(cpi_ctx, amount, decimals)?;
// Uses InterfaceAccount<'info, TokenAccount> + Interface<'info, TokenInterface>
```

---

## V37 - Token-2022 Transfer Hook Not Accounted For

**Detect:** `transfer_checked` CPI to Token-2022 mints without resolving and passing extra accounts required by the transfer hook extension.

**Vulnerable:**
```rust
transfer_checked(cpi_ctx, amount, decimals)?;
// Mint has transfer hook - extra accounts not passed via remaining_accounts
// Transfer reverts
```

**Exploit:** Protocol cannot transfer tokens with transfer hooks. DoS on deposits/withdrawals for affected mints.

**Secure:**
```rust
// Resolve hook accounts and pass via remaining_accounts
let hook_accounts = resolve_transfer_hook_accounts(&mint)?;
// Include in CPI
```

---

## V38 - Missing CPI Program ID Validation in Anchor

**Detect:** `/// CHECK:` on a program account instead of `Program<'info, T>`. CPI target program ID never validated.

**Vulnerable:**
```rust
/// CHECK: This is the token program
pub token_program: AccountInfo<'info>,
// No address validation - arbitrary CPI
```

**Secure:**
```rust
pub token_program: Program<'info, Token>,
// Or: #[account(address = spl_token::ID)]
```

---

## V39 - Cross-Program Reentrancy via CPI Callback

**Detect:** Program A makes CPI to untrusted program B, which calls back into program A. State partially updated before CPI - callback sees inconsistent state. Note: Solana's runtime prevents A→A reentrancy, but A→B→A is possible if different accounts are used.

**Vulnerable:**
```rust
// Program A: update partial state, then CPI to untrusted B
vault.pending_withdrawal = amount;  // partial state update
invoke(&ix_to_untrusted_b, &[...])?;
vault.balance -= amount;  // not yet executed when B calls back into A
```

**Exploit:** B calls back into A with different accounts, using the partially-updated state.

**Secure:**
```rust
// Update ALL state before CPI (checks-effects-interactions)
vault.balance -= amount;
vault.pending_withdrawal = 0;
invoke(&ix_to_untrusted_b, &[...])?;
```

---

## V40 - CPI to Upgradeable Program

**Detect:** `invoke` / `invoke_signed` targeting a program that is not immutable (upgrade authority != None). Target program can be maliciously upgraded between transactions.

**Vulnerable:**
```rust
invoke(&ix, &[target_program.clone(), ...])?;
// target_program could be upgraded to steal funds in next slot
```

**Secure:**
```rust
// Verify program is immutable: upgrade authority set to None
// Or: only CPI to known immutable programs (SPL Token, System Program)
// Or: validate upgrade authority is trusted (multisig, governance)
```

---

## V41 - Address Lookup Table Contains Signer

**Detect:** Signer pubkey included in ALT. Signer accounts must always be inline in the transaction message - ALT inclusion breaks signing validation.

**Vulnerable:**
```rust
// Client-side: putting signer in ALT
alt.entries.push(user_wallet.pubkey());  // breaks signing
```

**Secure:** Only non-signer accounts in ALT. Signer accounts always inline in transaction.

---

## V42 - Durable Nonce Not First Instruction

**Detect:** `AdvanceNonceAccount` instruction placed after index 0 in transaction using durable nonces.

**Vulnerable:**
```rust
// ix[0] = do_something, ix[1] = advance_nonce
// Nonce not advanced - transaction can be replayed
```

**Secure:** `AdvanceNonceAccount` must be instruction index 0.

---

## V43 - Token-2022 Permanent Delegate

**Detect:** Protocol accepting arbitrary mints without checking for `ExtensionType::PermanentDelegate`. Vaults/pools/escrows holding tokens with permanent delegates.

**Vulnerable:**
```rust
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    transfer_checked(cpi_ctx, amount, decimals)?;
    // No check if mint has PermanentDelegate extension
    // Delegate can transfer/burn tokens from vault at any time
}
```

**Exploit:** Permanent delegate transfers all deposited tokens out of vault without any signature from the vault authority.

**Secure:**
```rust
let mint_data = ctx.accounts.mint.to_account_info().try_borrow_data()?;
let mint_state = PodStateWithExtensions::<PodMint>::unpack(&mint_data)?;
require!(mint_state.get_extension::<PermanentDelegate>().is_err(), NoPermanentDelegates);
```

---

## V44 - Token-2022 Transfer Fee Accounting Mismatch

**Detect:** `transfer_checked` CPI followed by bookkeeping that uses the requested amount instead of actual received amount. Missing balance-before/balance-after pattern.

**Vulnerable:**
```rust
transfer_checked(user_token, vault_token, authority, amount, decimals)?;
vault.deposits[user] += amount;  // BUG: vault received (amount - transfer_fee)
```

**Exploit:** Accounting credits more than received. Over time, vault becomes insolvent - last withdrawers get nothing.

**Secure:**
```rust
let pre = vault_token.amount;
transfer_checked(user_token, vault_token, authority, amount, decimals)?;
ctx.accounts.vault_token.reload()?;
vault.deposits[user] += ctx.accounts.vault_token.amount - pre;  // actual received
```

---

## V45 - Token-2022 Non-Transferable Extension

**Detect:** Protocol assumes tokens are freely transferable without checking `ExtensionType::NonTransferable`. Soulbound tokens cannot be transferred between accounts.

**Vulnerable:**
```rust
// Vault accepts any mint - including soulbound tokens
// When user tries to withdraw, transfer fails permanently
```

**Secure:**
```rust
require!(mint_state.get_extension::<NonTransferable>().is_err(), NonTransferableNotSupported);
```

---

## V46 - Mint Close Authority - Reinitialization Bypass

**Detect:** Protocol accepting mints with `MintCloseAuthority` extension without re-validating mint properties on each interaction. Mint can be closed and re-created at same address with different extensions.

**Vulnerable:**
```rust
// Store mint pubkey on initialization
pool.mint = mint.key();
// Later: trust the mint without re-checking extensions
// Mint was closed and re-created without TransferFee extension → bypass fees
```

**Exploit:** Attacker creates mint → registers in protocol → closes mint → re-creates at same address with different extensions (no KYC, no fees, no soulbound). Old token accounts survive.

**Secure:**
```rust
// Re-validate mint extensions on every interaction, or reject mints with MintCloseAuthority
require!(mint_state.get_extension::<MintCloseAuthority>().is_err(), MintCloseAuthorityNotSupported);
```

---

## V47 - CPI Ordering - Lamports Before Completion

**Detect:** Manual lamport transfer (via `**lamports.borrow_mut()`) before CPI `close_account` completes. Violates Solana's instruction-level lamport balance invariant.

**Vulnerable:**
```rust
// Transfer lamports to bidder manually
**ctx.accounts.escrow.lamports.borrow_mut() -= refund_amount;
**ctx.accounts.bidder.lamports.borrow_mut() += refund_amount;
// Then CPI close_account on escrow - fails with UnbalancedInstruction
```

**Exploit:** **OneMind Auction audit** - auction cancellation permanently failed when bids existed. Funds locked.

**Secure:**
```rust
// Let CPI handle lamport transfers, or do manual transfers AFTER all CPIs complete
close_account(cpi_ctx)?;  // handles lamport transfer atomically
```

---

## V48 - Security Dependency Chain

**Detect:** `Account<'info, T>` without seeds/bump or address constraint used as root of trust for downstream `has_one`/`constraint` checks. Unconstrained root poisons all derived validations.

**Vulnerable:**
```rust
pub config: Account<'info, Config>,          // NO seeds, NO address constraint
#[account(constraint = vault.config == config.key())]
pub vault: Account<'info, Vault>,            // validates against fake config
#[account(constraint = position.vault == vault.key())]
pub position: Account<'info, Position>,      // cascading fake validation
```

**Exploit:** Entire validation chain is meaningless. Attacker provides crafted config → derives matching vault → accesses any position.

**Secure:**
```rust
#[account(seeds = [b"config"], bump)]  // PDA - unforgeable root
pub config: Account<'info, Config>,
```

---

## V49 - Dangling References After Account Close via CPI

**Detect:** Account data cached (deserialized) before CPI that closes the account. Cached data used after CPI - references stale/zeroed memory.

**Vulnerable:**
```rust
let balance = ctx.accounts.source.amount;  // cache
close_account_cpi(ctx)?;                    // source closed
msg!("Had balance: {}", balance);           // stale - source may be zeroed
// Worse: ctx.accounts.source.amount - dangling reference
```

**Secure:**
```rust
let balance = ctx.accounts.source.amount;
require!(balance > 0, EmptyAccount);
// Close LAST, after all reads
close_account_cpi(ctx)?;
// Do NOT read from source after close
```

---

## V50 - Account Reassignment Data Wipe

**Detect:** `account.assign(&system_program::ID)` followed by `account.assign(program_id)` - temporary ownership change zeroes account data.

**Vulnerable:**
```rust
account.assign(&system_program::ID);  // runtime zeroes data on ownership change
account.assign(ctx.program_id);        // reassign back - but data is gone
```

**Exploit:** All account state permanently destroyed. Program functions referencing this account break.

**Secure:** Never temporarily reassign account ownership. If ownership must change, backup and restore data explicitly.
