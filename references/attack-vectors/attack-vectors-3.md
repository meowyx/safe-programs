# Attack Vectors Reference - Arithmetic, Tokens & State Management (3/4)

> Part 3 of 5 · Vectors 51–75 of 105 total
> Covers: integer safety, precision loss, token operations, state lifecycle, fee logic, Token-2022 extensions

---

## V51 - Integer Overflow via Unchecked Arithmetic

**Detect:** Direct `+`, `-`, `*`, `/` operators on integer types without `checked_*` wrappers. Missing `overflow-checks = true` in `Cargo.toml [profile.release]`. Note: Anchor's default template sets `overflow-checks = true`, but verify it hasn't been removed.

**Vulnerable:**
```rust
vault.balance = vault.balance + amount;  // wraps on overflow in release mode!
// u64::MAX - 100 + 200 = 99
```

**Exploit:** Attacker deposits `u64::MAX - current_balance + desired_balance`, wraps to desired value.

**Secure:**
```rust
vault.balance = vault.balance.checked_add(amount).ok_or(ErrorCode::Overflow)?;
// Also verify: Cargo.toml [profile.release] overflow-checks = true
```

---

## V52 - Integer Underflow on Balance Subtraction

**Detect:** `balance - amount` or `balance -= amount` without prior `require!(balance >= amount)` or `checked_sub`.

**Vulnerable:**
```rust
vault.balance -= withdrawal_amount;  // wraps to u64::MAX if amount > balance
```

**Secure:**
```rust
vault.balance = vault.balance.checked_sub(amount).ok_or(ErrorCode::InsufficientFunds)?;
```

---

## V53 - Division Before Multiplication - Precision Loss

**Detect:** Division operator or `checked_div` followed by multiplication on integer types. `(a / b) * c` pattern.

**Vulnerable:**
```rust
let share_value = (user_deposit / total_supply) * price;
// If user_deposit < total_supply, division truncates to 0 → share_value = 0
```

**Exploit:** **Neodyme $2.6B disclosure** - rounding errors in lending protocol rate calculations. Attacker gets free operations when amounts truncate to zero.

**Secure:**
```rust
let share_value = user_deposit.checked_mul(price)?.checked_div(total_supply)?;
// Multiply first, then divide - preserves precision
// Use u128 for intermediate results
```

---

## V54 - Division by Zero

**Detect:** Division where divisor can be zero: `total_supply`, `pool_balance`, `shares_outstanding`, `total_staked`. Any division without prior zero check or `checked_div`.

**Vulnerable:**
```rust
let reward_per_share = total_rewards / total_staked;  // panics if total_staked == 0
```

**Exploit:** **Kamino Lend (W7)**, **Watt Protocol (H1)** - division by zero on first interaction or empty pool state. Transaction panics → DoS.

**Secure:**
```rust
let reward_per_share = total_rewards.checked_div(total_staked).unwrap_or(0);
// Or: require!(total_staked > 0, NoStakers);
```

---

## V55 - Unsafe Integer Casting - `as` Truncation and Sign Reinterpretation

**Detect:** `as u32`, `as u16`, `as u8` - narrowing casts using `as` keyword. `as u64` on `i64` - signed-to-unsigned reinterpretation. `as i64` on large `u64` - unsigned-to-signed overflow. Any `as` cast between integer types without `try_from`.

**Vulnerable:**
```rust
let amount_u32 = amount_u64 as u32;  // silently drops high bits
// 0x1_0000_0064 as u32 = 100 - attacker bypasses amount check

let price = oracle_price_feed.price;  // i64, can be negative
let value = amount * (price as u64);  // -1i64 as u64 = 18446744073709551615
```

**Secure:**
```rust
let amount_u32 = u32::try_from(amount_u64).map_err(|_| ErrorCode::CastOverflow)?;

require!(price > 0, NegativePrice);
let price_u64 = u64::try_from(price).map_err(|_| ErrorCode::InvalidCast)?;
```

---

## V56 - Rounding Direction Exploitation

**Detect:** `try_round_u64()` in share/token calculations. Rounding that favors users on both deposit AND withdraw paths. Missing directional rounding.

**Vulnerable:**
```rust
// Deposit: shares = collateral.try_div(rate)?.try_round_u64()?;  // rounds UP → user gets more
// Withdraw: tokens = shares.try_div(rate)?.try_round_u64()?;     // rounds UP → user gets more
```

**Exploit:** Repeated small deposit/withdraw cycles drain the pool by rounding profit each cycle.

**Secure:**
```rust
// Deposit: round DOWN (fewer shares for user): try_floor_u64()
// Withdraw: round DOWN (fewer tokens for user): try_floor_u64()
// Protocol always favors the pool
```

---

## V57 - First Depositor Vault Inflation Attack

**Detect:** Vault/pool with share-based accounting where first deposit has no minimum. Share calculation: `shares = deposit * total_shares / total_assets` where `total_shares` and `total_assets` start at 0.

**Vulnerable:**
```rust
let shares = if total_shares == 0 { deposit_amount } else {
    deposit_amount * total_shares / total_assets
};
// Attacker: deposit 1 (gets 1 share), then donate 1e9 tokens directly to vault
// total_assets = 1e9+1, total_shares = 1
// Victim deposits 1e9 tokens: shares = 1e9 * 1 / (1e9+1) = 0 shares!
```

**Exploit:** First depositor steals all subsequent deposits via share price inflation.

**Secure:**
```rust
// Virtual offset: start with non-zero virtual shares/assets
let shares = (deposit_amount + VIRTUAL_OFFSET) * total_shares / (total_assets + VIRTUAL_OFFSET);
// Or: require!(shares > 0, ZeroShares);
// Or: dead shares minted on initialization
```

---

## V58 - Round-Trip Profit - Deposit/Withdraw Arbitrage

**Detect:** Inconsistent rounding between deposit and withdraw paths. Test: `deposit(X) → withdraw(all) > X`.

**Vulnerable:**
```rust
// Deposit rounds UP shares, withdraw rounds UP tokens
// Each round trip: user profits a small amount
```

**Secure:** Both paths round in protocol's favor. Add round-trip invariant test.

---

## V59 - Saturating Math Misuse

**Detect:** `saturating_sub`, `saturating_add`, `saturating_mul` used in financial calculations where overflow/underflow should be an error, not silently clamped.

**Vulnerable:**
```rust
let remaining = health_factor.saturating_sub(penalty);
// If penalty > health_factor, silently returns 0 instead of reverting
// Unhealthy position treated as healthy
```

**Secure:**
```rust
let remaining = health_factor.checked_sub(penalty).ok_or(ErrorCode::Unhealthy)?;
```

---

## V60 - Price Slippage Not Enforced

**Detect:** Swap/purchase/trade functions without `min_amount_out`, `max_price`, or `expected_price` parameter. Price-sensitive operations without user-provided bounds.

**Vulnerable:**
```rust
pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
    let amount_out = calculate_output(amount_in, &ctx.accounts.pool)?;
    transfer_to_user(ctx, amount_out)?;
    // No minimum_amount_out check - sandwich attack
}
```

**Exploit:** MEV bot front-runs: manipulate price → user swaps at bad rate → back-run to profit.

**Secure:**
```rust
pub fn swap(ctx: Context<Swap>, amount_in: u64, min_amount_out: u64) -> Result<()> {
    let amount_out = calculate_output(amount_in, &ctx.accounts.pool)?;
    require!(amount_out >= min_amount_out, SlippageExceeded);
}
```

---

## V61 - Lamport Balance Invariant Violation

**Detect:** Manual lamport manipulation that creates/destroys lamports. Sum of debits must equal sum of credits across all accounts in an instruction.

**Vulnerable:**
```rust
**account_a.lamports.borrow_mut() += 1000;
// No corresponding debit from another account - runtime rejects
```

**Secure:** All lamport transfers balanced. Use System Program for transfers.

---

## V62 - Rent Lamports to Arbitrary Destination

**Detect:** Account close with rent lamports transferred to user-specified destination without validation. `close = recipient` where recipient is unvalidated.

**Vulnerable:**
```rust
// Close sends rent to attacker-provided address instead of original payer
```

**Secure:**
```rust
#[account(mut, close = original_payer)]  // hardcoded or PDA-controlled destination
```

---

## V63 - Token Dust Account Poisoning

**Detect:** Token account close logic that doesn't handle non-zero dust balance. `close_account` requires zero balance.

**Vulnerable:**
```rust
// Attacker deposits 1 token → account can never be closed
// Rent permanently locked
```

**Secure:**
```rust
// Sweep dust before close, or reject deposits below dust threshold
// For Token-2022: also check withheld transfer fees via .closable()
```

---

## V64 - Fee Bypass on Alternative Code Path

**Detect:** Fee applied in normal path but not in emergency/alternative path. Multiple withdrawal/exit functions with inconsistent fee application.

**Vulnerable:**
```rust
pub fn withdraw(ctx, amount) { let fee = amount * fee_bps / 10000; transfer(amount - fee); }
pub fn emergency_withdraw(ctx, amount) { transfer(amount); }  // no fee!
```

**Secure:** Single fee calculation function used across all exit paths.

---

## V65 - Pre-Fee / Post-Fee Amount Confusion

**Detect:** Fee calculated on input amount, capacity/limit check uses post-fee amount (or vice versa). Inconsistent amount reference.

**Vulnerable:**
```rust
let fee = amount * fee_bps / 10000;
require!(amount <= vault.capacity);     // checks pre-fee
vault.balance += amount - fee;          // stores post-fee
// Vault can exceed capacity by fee amount
```

**Exploit:** **Pump Science (M-01)** - fee calculated on input amount before `apply_buy` recomputed the actual SOL amount. Last buyer pays wrong fee.

**Secure:** Consistent: either pre-fee throughout or post-fee throughout. Fee deducted atomically.

---

## V66 - Token Decimals Mismatch

**Detect:** Hardcoded decimal assumptions (e.g., `* 1_000_000` for USDC) without reading `mint.decimals`. Missing `transfer_checked` (requires decimals param).

**Vulnerable:**
```rust
let value_usd = token_amount * price / 1_000_000;  // assumes 6 decimals
// Fails for tokens with 9 decimals - off by 1000x
```

**Secure:**
```rust
let value = token_amount.checked_mul(price)?.checked_div(10u64.pow(mint.decimals as u32))?;
```

---

## V67 - Coupled State Fields Not Reset Atomically

**Detect:** Logically coupled fields (e.g., `shares_pending` + `total_shares`) where one is reset but not the other. Struct reset/close that doesn't zero all related fields.

**Vulnerable:**
```rust
user_state.shares_pending = 0;
// user_state.rewards_owed NOT reset - stale rewards claimable
```

**Exploit:** **Watt Protocol (C4)** - unstake withdrew full balance but position record remained intact. User re-stakes to multiply position.

**Secure:** Reset all coupled fields atomically in same instruction.

---

## V68 - Time Unit Mismatch - Slots vs Seconds

**Detect:** Code mixing `clock.slot` with `clock.unix_timestamp`. One part uses slots (~400ms), another uses seconds, compared directly.

**Vulnerable:**
```rust
let lock_end = clock.unix_timestamp + 86400;  // 1 day in seconds
// Later: if clock.slot > lock_end { unlock(); }  // slot number >> seconds - unlocks immediately
```

**Secure:** Single canonical time unit. Field names annotated: `_slot`, `_timestamp_secs`.

---

## V69 - Account Data Realloc Without Zero-Init

**Detect:** `realloc` with `zero = false` or `.realloc(new_size, false)`. After shrink + expand, old data from previous allocation leaks into new space.

**Vulnerable:**
```rust
#[account(mut, realloc = new_size, realloc::payer = payer, realloc::zero = false)]
// If account previously shrunk then re-expanded, old data leaks
```

**Secure:**
```rust
realloc::zero = true  // zeroes new space
```

---

## V70 - Unbounded Collection - Compute DoS

**Detect:** Loops over `Vec`, `remaining_accounts`, or linked structures without upper bound. Variable-length iteration that can exceed 200K (default) or 1.4M (max) compute units.

**Vulnerable:**
```rust
for user in ctx.remaining_accounts.iter() {
    process_user(user)?;  // unbounded - grows until compute exceeded
}
```

**Exploit:** Attacker grows collection until instruction permanently exceeds compute budget → DoS.

**Secure:**
```rust
const MAX_BATCH: usize = 32;
require!(ctx.remaining_accounts.len() <= MAX_BATCH, TooManyAccounts);
```

---

## V71 - Missing Preprocessing on Share Transfer

**Detect:** LP token or share transfer without settling pending fees/rewards on both source and destination first.

**Vulnerable:**
```rust
pub fn transfer_shares(from, to, amount) {
    from.shares -= amount;
    to.shares += amount;
    // from's pending rewards NOT settled - lost
    // to receives rewards they never earned
}
```

**Secure:** Settle rewards on both accounts before any share balance change.

---

## V72 - Token-2022 Interest-Bearing Token Not Accounted

**Detect:** Token-2022 interest-bearing extension where program reads raw `amount` instead of effective (interest-adjusted) balance.

**Vulnerable:**
```rust
let balance = token_account.amount;  // raw balance - doesn't include accrued interest
// Under-accounting if interest has accrued
```

**Secure:** Detect interest-bearing extension and calculate effective balance.

---

## V73 - Token-2022 Transfer Fee Blocks Account Close

**Detect:** `close_account` CPI guarded only by `amount == 0` without checking `.closable()` on fee/confidential transfer extensions. Withheld fees prevent closure.

**Vulnerable:**
```rust
if token_account.amount == 0 {
    close_account(cpi_ctx)?;  // FAILS if withheld_amount > 0
}
```

**Exploit:** Protocol cannot close token accounts, rent permanently locked.

**Secure:**
```rust
let state = PodStateWithExtensions::<PodAccount>::unpack(&data)?;
if let Ok(fee_state) = state.get_extension::<TransferFeeAmount>() {
    fee_state.closable()?;  // checks withheld == 0
}
// Harvest withheld fees to mint first, then close
```

---

## V74 - Floating-Point Arithmetic in Financial Logic

**Detect:** `f64`, `f32`, `as f64` in any financial calculation. Direct `==` comparison on floats. `ui_amount` from SPL Token used in arithmetic.

**Vulnerable:**
```rust
let ui_amount = token_account.amount as f64 / 10f64.powi(decimals as i32);
if ui_amount != 1.0 { return Err(InvalidAmount); }  // float comparison - unreliable
```

**Exploit:** **Solodit Escrow audit (Critical)** - f64 precision loss caused incorrect token amounts. Float comparison `!= 1.0` fails due to floating-point representation.

**Secure:**
```rust
// Use integer arithmetic with explicit scaling
let expected_amount = 10u64.pow(decimals as u32);  // 1.0 in base units
require!(token_account.amount == expected_amount, InvalidAmount);
```

---

## V75 - Lamport / SOL Denomination Confusion

**Detect:** Hardcoded lamport amounts that are wrong by factor of 1000 (1 SOL = 1_000_000_000 lamports, not 1_000_000). Constants like `LAMPORTS_PER_SOL` not used.

**Vulnerable:**
```rust
const LISTING_FEE: u64 = 1_000_000;  // intended: 1 SOL - actual: 0.001 SOL (off by 1000x)
```

**Exploit:** **Solodit Escrow audit (Critical)** - fees 1000x lower than intended due to missing 3 zeros.

**Secure:**
```rust
use solana_program::native_token::LAMPORTS_PER_SOL;
const LISTING_FEE: u64 = LAMPORTS_PER_SOL;  // 1_000_000_000
```
