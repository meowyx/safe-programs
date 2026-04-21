# Attack Vectors Reference - Oracle, DeFi & Platform-Level (4/4)

> Part 4 of 5 · Vectors 76–100 of 105 total
> Covers: oracle security, staking/rewards, DeFi protocol patterns, compute/platform, input validation, real-world exploit patterns

---

## V76 - Stale Oracle Price

**Detect:** Oracle `publish_time`, `last_update`, `updated_at` field read but not compared against `clock.unix_timestamp`. Or: oracle price used without any timestamp check at all.

**Vulnerable:**
```rust
let price_feed = load_price_feed_from_account_info(&oracle_ai)?;
let price = price_feed.get_price_unchecked();  // no staleness check
let value = amount.checked_mul(price.price as u64)?;
```

**Exploit:** Oracle stops updating (network issues, feed decommissioned). Attacker trades at outdated favorable price. **Mango Markets** - attacker manipulated a thinly-traded oracle to inflate collateral value.

**Secure:**
```rust
let price = price_feed.get_price_no_older_than(&clock, MAX_STALENESS_SECS)?;
// Or manual: require!(clock.unix_timestamp - price.publish_time <= MAX_AGE, StaleOracle);
```

---

## V77 - Oracle Confidence Interval Not Validated

**Detect:** Pyth `price.conf` field never checked. Price used without `conf / price` ratio validation. `get_price_unchecked()` instead of `get_price_no_older_than()` with confidence check.

**Vulnerable:**
```rust
let price = price_feed.get_price_unchecked();
let value = collateral * price.price as u64;
// price.conf could be 50% of price - completely unreliable
```

**Exploit:** During volatile markets, confidence widens massively. Attacker borrows against inflated collateral when confidence is ±50% of price.

**Secure:**
```rust
let price = price_feed.get_price_no_older_than(&clock, MAX_AGE)?;
require!(
    price.conf.checked_mul(100)?.checked_div(price.price.unsigned_abs())? <= MAX_CONF_PCT,
    OracleConfidenceTooWide
);
```

---

## V78 - Oracle Status Not Checked

**Detect:** Pyth `PriceStatus` or Switchboard `AggregatorAccountData` status field not validated. Price used regardless of trading/halted status.

**Vulnerable:**
```rust
let price_account: PriceFeed = load_price_feed(&oracle)?;
// No status check - price may be from halted/unknown state
let value = amount * price_account.get_price_unchecked().price as u64;
```

**Secure:**
```rust
let price = price_feed.get_price_no_older_than(&clock, MAX_AGE)?;
// get_price_no_older_than returns error if status != Trading
// For Switchboard: require!(aggregator.check_staleness(...).is_ok());
```

---

## V79 - Fake Oracle Account - Missing Owner Validation

**Detect:** Oracle `AccountInfo` deserialized without owner check. `/// CHECK:` annotation on oracle account. Oracle account key not validated against stored config or hardcoded address.

**Vulnerable:**
```rust
/// CHECK: oracle account
pub oracle: AccountInfo<'info>,
// Attacker passes crafted account with fabricated price data
let price_feed = load_price_feed_from_account_info(&ctx.accounts.oracle)?;
```

**Exploit:** Attacker creates an account with the same data layout as a price feed, sets any price they want, passes it as the oracle.

**Secure:**
```rust
#[account(
    address = pool.oracle_address,  // stored on init
    owner = PYTH_PROGRAM_ID @ ErrorCode::InvalidOracle
)]
pub oracle: AccountInfo<'info>,
// Or: require!(*oracle.owner == pyth_solana_receiver_sdk::ID);
```

---

## V80 - On-Chain Spot Price as Valuation Source

**Detect:** Pool `reserve_a / reserve_b` or `token_account.amount` used for pricing instead of oracle. AMM `get_spot_price()` used in lending/liquidation logic.

**Vulnerable:**
```rust
let price = pool.reserve_sol.checked_div(pool.reserve_token)?;
// Spot price - manipulable within a single transaction
let collateral_value = user_tokens.checked_mul(price)?;
```

**Exploit:** **Mango Markets ($115M)** - attacker manipulated MNGO/USDC spot price on their own market to inflate collateral, then borrowed against it across all markets. Flash loan → pump spot price → borrow → repay flash loan.

**Secure:**
```rust
// Use oracle (Pyth/Switchboard) for valuation, NOT spot price
let oracle_price = get_oracle_price(&ctx.accounts.oracle, &clock)?;
let collateral_value = user_tokens.checked_mul(oracle_price)?;
// For AMMs: use TWAP, not instantaneous spot
```

---

## V81 - Retroactive Oracle Pricing

**Detect:** Settlement/close/liquidation uses current oracle price for positions opened at a different time. Position struct missing `entry_price` or `open_price` field.

**Vulnerable:**
```rust
pub fn settle_position(ctx: Context<Settle>) -> Result<()> {
    let current_price = get_oracle_price(&ctx.accounts.oracle)?;
    let pnl = (current_price - position.entry_price) * position.size;
    // But position.entry_price was never stored - it's always current_price!
}

pub fn open_position(ctx: Context<Open>, size: u64) -> Result<()> {
    position.size = size;
    // Missing: position.entry_price = get_oracle_price(&oracle)?;
}
```

**Secure:**
```rust
pub fn open_position(ctx: Context<Open>, size: u64) -> Result<()> {
    position.size = size;
    position.entry_price = get_oracle_price(&ctx.accounts.oracle)?;
    position.open_slot = clock.slot;
}
```

---

## V82 - Staking Reward Index Not Updated Before Balance Change

**Detect:** `stake()` or `unstake()` function that modifies `user.staked_amount` or `pool.total_staked` without first calling reward accumulator update. `reward_per_token` or `reward_index` calculation missing before balance mutation.

**Vulnerable:**
```rust
pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    let user = &mut ctx.accounts.user_stake;
    // BUG: reward_per_token not updated before total_staked changes
    user.staked_amount += amount;
    pool.total_staked += amount;
    // New staker dilutes existing stakers' pending rewards
}
```

**Exploit:** Attacker stakes right before reward distribution, captures share of rewards earned entirely by others. Or: existing staker's pending rewards silently reduced when total_staked increases.

**Secure:**
```rust
pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    let user = &mut ctx.accounts.user_stake;
    // Update global accumulator FIRST
    pool.reward_per_token += pending_rewards.checked_div(pool.total_staked)?;
    // Settle user's pending rewards BEFORE balance change
    user.pending_rewards += user.staked_amount * (pool.reward_per_token - user.last_reward_per_token);
    user.last_reward_per_token = pool.reward_per_token;
    // NOW safe to change balances
    user.staked_amount += amount;
    pool.total_staked += amount;
}
```

---

## V83 - Flash Stake/Unstake Reward Capture

**Detect:** No minimum staking duration. `unstake()` callable in same slot/transaction as `stake()`. Missing `lockup_until` or `last_stake_slot` check.

**Vulnerable:**
```rust
pub fn unstake(ctx: Context<Unstake>) -> Result<()> {
    let user = &mut ctx.accounts.user_stake;
    let rewards = calculate_rewards(user)?;
    // No lockup check - can stake and unstake in same transaction
    transfer_rewards(ctx, rewards)?;
    user.staked_amount = 0;
}
```

**Exploit:** Attacker: stake large amount → trigger reward distribution → claim rewards → unstake. All in one transaction. Zero capital commitment, full reward capture.

**Secure:**
```rust
pub fn unstake(ctx: Context<Unstake>) -> Result<()> {
    let clock = Clock::get()?;
    require!(
        clock.unix_timestamp >= user.last_stake_time + MIN_LOCKUP_SECS,
        LockupNotExpired
    );
}
```

---

## V84 - Reward Dilution via Direct Token Transfer

**Detect:** Reward calculation using `token_account.amount` (raw balance) instead of internal `total_staked` state variable. `reward_per_token = rewards / token_account.amount` pattern.

**Vulnerable:**
```rust
let total = ctx.accounts.staking_vault.amount;  // raw SPL balance
let reward_per_token = new_rewards.checked_div(total)?;
// Attacker transfers tokens directly to vault → inflates denominator → dilutes rewards
```

**Exploit:** Attacker sends tokens directly to the staking vault (not through `stake()`). `total` increases but no shares are minted. All stakers' reward rates diluted.

**Secure:**
```rust
let total = pool.total_staked;  // internal accounting, not raw balance
let reward_per_token = new_rewards.checked_div(total)?;
// Direct transfers don't affect total_staked
```

---

## V85 - Cooldown/Unstake Period Griefable

**Detect:** Unstaking cooldown resets on any deposit, including deposits from other users. `last_deposit_time` updated by non-owner. Cooldown field in shared account.

**Vulnerable:**
```rust
pub fn deposit_to_stake(ctx: Context<DepositToStake>, amount: u64) -> Result<()> {
    let stake = &mut ctx.accounts.stake_account;
    stake.amount += amount;
    stake.cooldown_start = Clock::get()?.unix_timestamp;  // resets on ANY deposit
    // Anyone can deposit dust to reset victim's cooldown
}
```

**Exploit:** Attacker deposits 1 lamport worth of tokens to victim's stake account every epoch, perpetually resetting their cooldown. Victim can never unstake.

**Secure:**
```rust
// Only reset cooldown on owner-initiated deposits
require!(ctx.accounts.depositor.key() == stake.owner, Unauthorized);
// Or: track cooldown per-deposit, not per-account
// Or: reject deposits below minimum threshold
```

---

## V86 - Self-Liquidation Profit

**Detect:** Liquidation function without `require!(liquidator != borrower)`. Liquidation bonus/discount exceeds penalty. Liquidator receives more value than position's bad debt.

**Vulnerable:**
```rust
pub fn liquidate(ctx: Context<Liquidate>, amount: u64) -> Result<()> {
    let bonus = amount * LIQUIDATION_BONUS_BPS / 10000;  // 10% bonus
    // No check that liquidator != position owner
    transfer_collateral(ctx, amount + bonus)?;
    // Self-liquidation: user pays off own debt, gets 10% bonus from protocol
}
```

**Secure:**
```rust
require!(
    ctx.accounts.liquidator.key() != ctx.accounts.position.owner,
    SelfLiquidationNotAllowed
);
```

---

## V87 - Token-2022 CPIGuard and DefaultAccountState DoS

**Detect:** Protocol performing CPI token transfers without checking for CPIGuard extension on source account. Protocol creating/receiving token accounts without checking mint's `DefaultAccountState` extension (frozen-by-default).

**Vulnerable:**
```rust
// CPIGuard: CPI transfer silently rejected
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // If user's token account has CPIGuard enabled, this CPI transfer FAILS
    token_interface::transfer_checked(cpi_ctx, amount, decimals)?;
    // User's funds permanently stuck - can't withdraw via CPI
}

// DefaultAccountState: transfers to new ATAs fail
pub fn distribute(ctx: Context<Distribute>, amount: u64) -> Result<()> {
    // If mint has DefaultAccountState::Frozen, newly created ATAs start frozen
    token_interface::transfer_checked(cpi_ctx, amount, decimals)?;
    // Transfer to frozen account fails - rewards/payouts stuck
}
```

**Exploit:** CPIGuard: User enables CPIGuard on their token account, then deposits into protocol. Protocol can never CPI-transfer tokens back - permanent lock. DefaultAccountState: Mint creates frozen accounts by default. Protocol creates ATA for user, attempts transfer - fails because destination is frozen.

**Secure:**
```rust
// Check CPIGuard before CPI operations
let account_data = ctx.accounts.source.to_account_info().try_borrow_data()?;
let state = StateWithExtensions::<Token2022Account>::unpack(&account_data)?;
if let Ok(cpi_guard) = state.get_extension::<CpiGuard>() {
    if bool::from(cpi_guard.lock_cpi) {
        return err!(ErrorCode::CpiGuardEnabled);  // reject or use alternative flow
    }
}

// Check DefaultAccountState on mint
let mint_data = ctx.accounts.mint.to_account_info().try_borrow_data()?;
let mint_state = StateWithExtensions::<Mint>::unpack(&mint_data)?;
if let Ok(default_state) = mint_state.get_extension::<DefaultAccountState>() {
    if u8::from(default_state.state) == AccountState::Frozen as u8 {
        return err!(ErrorCode::MintCreatesFrozenAccounts);
    }
}
```

---

## V88 - Compute Budget Exhaustion DoS

**Detect:** Unbounded loops over `Vec`, `remaining_accounts`, or linked structures. Recursive calculations. Multiple CPIs in a single instruction. No `ComputeBudgetInstruction::set_compute_unit_limit`.

**Vulnerable:**
```rust
pub fn distribute_rewards(ctx: Context<Distribute>) -> Result<()> {
    for (i, account) in ctx.remaining_accounts.iter().enumerate() {
        let user: Account<UserStake> = Account::try_from(account)?;
        // Each iteration: deserialize + calculate + CPI transfer
        // 50+ users → exceeds 200K default, possibly even 1.4M max compute
        transfer_reward(&user)?;
    }
}
```

**Exploit:** Attacker grows the user set until the instruction permanently exceeds compute budget. Function becomes permanently uncallable - protocol DoS.

**Secure:**
```rust
const MAX_BATCH: usize = 10;
require!(ctx.remaining_accounts.len() <= MAX_BATCH, BatchTooLarge);
// Client-side: add ComputeBudgetInstruction::set_compute_unit_limit(400_000)
// Design: paginated processing with cursor stored on-chain
```

---

## V89 - Heap Exhaustion - 32KB Limit

**Detect:** Large `Vec` allocations, recursive data structures, unbounded deserialization (`BorshDeserialize` on variable-length types), or `Box::new` in loops. Solana programs have a 32KB heap limit.

**Vulnerable:**
```rust
pub fn process(ctx: Context<Process>, data: Vec<u8>) -> Result<()> {
    let parsed: Vec<UserRecord> = BorshDeserialize::deserialize(&mut &data[..])?;
    // 1000 UserRecords × 200 bytes = 200KB → heap exhaustion → program crash
    let mut results = Vec::with_capacity(parsed.len());
    for record in parsed { results.push(transform(record)?); }
}
```

**Exploit:** Attacker passes instruction data with many items, heap allocation exceeds 32KB, transaction panics. Permanent DoS if this function is required for protocol operation.

**Secure:**
```rust
require!(data.len() <= MAX_INPUT_SIZE, InputTooLarge);
// Process in fixed-size batches
// Use zero-copy deserialization: #[account(zero_copy)] or bytemuck
// Avoid Vec allocations - use fixed-size arrays or AccountLoader<'info, T>
```

---

## V90 - Missing Same-Asset Swap Check

**Detect:** Swap function where `input_mint == output_mint` is not rejected. `token_a_mint` and `token_b_mint` not compared.

**Vulnerable:**
```rust
pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
    // No check: ctx.accounts.input_mint.key() != ctx.accounts.output_mint.key()
    let amount_out = calculate_output(amount_in, &ctx.accounts.pool)?;
    transfer_in(ctx, amount_in)?;
    transfer_out(ctx, amount_out)?;
    // Same-token swap: fee extracted from pool without real economic activity
}
```

**Secure:**
```rust
require!(
    ctx.accounts.input_mint.key() != ctx.accounts.output_mint.key(),
    SameAssetSwap
);
```

---

## V91 - Missing Deadline on Time-Sensitive Operations

**Detect:** Swap, trade, deposit, or any price-sensitive instruction without `deadline`, `valid_until`, or `expires_at` parameter. No `clock.unix_timestamp` comparison against a user-supplied expiry.

**Vulnerable:**
```rust
pub fn swap(ctx: Context<Swap>, amount_in: u64, min_out: u64) -> Result<()> {
    // Has slippage protection but NO deadline
    // Transaction can sit pending, execute hours later at stale conditions
    let out = calculate_output(amount_in)?;
    require!(out >= min_out, SlippageExceeded);
}
```

**Exploit:** Validator holds transaction, executes it much later when market conditions differ. Even with slippage protection, user may get the minimum acceptable amount when they could have gotten better elsewhere if the tx had failed promptly.

**Secure:**
```rust
pub fn swap(ctx: Context<Swap>, amount_in: u64, min_out: u64, deadline: i64) -> Result<()> {
    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= deadline, TransactionExpired);
}
```

---

## V92 - Signature Replay Without Nonce

**Detect:** `Ed25519Program` or `Secp256k1Program` signature verification without including a nonce, sequence number, or domain separator in the signed message. Signed message missing program ID or chain context.

**Vulnerable:**
```rust
// Signed message: [amount, recipient]
let msg = [amount.to_le_bytes(), recipient.to_bytes()].concat();
verify_ed25519_signature(&signer_pubkey, &msg, &signature)?;
// Same signature valid forever - replay on every call
```

**Exploit:** Attacker captures a valid signed message, replays it indefinitely. Each replay executes the same operation (transfer, approval, etc.) without the signer's knowledge.

**Secure:**
```rust
// Include nonce + program_id + chain context in signed message
let msg = [
    amount.to_le_bytes().as_ref(),
    recipient.as_ref(),
    nonce.to_le_bytes().as_ref(),  // increment after use
    ctx.program_id.as_ref(),
].concat();
verify_ed25519_signature(&signer_pubkey, &msg, &signature)?;
user_state.nonce += 1;  // prevent replay
```

---

## V93 - On-Chain Randomness Manipulation

**Detect:** `clock.slot`, `clock.unix_timestamp`, `recent_slothashes`, or blockhash used as randomness source. Any `hash()` of predictable on-chain data used for lottery, selection, or distribution.

**Vulnerable:**
```rust
let random_seed = clock.slot.to_le_bytes();
let hash = hashv(&[&random_seed, user.key().as_ref()]);
let winner_index = u64::from_le_bytes(hash.to_bytes()[..8].try_into()?) % total_entries;
// Validator/attacker can predict slot → predict winner → only enter when they win
```

**Exploit:** Validators choose which slot to include the transaction in. Attackers can simulate outcomes for each slot and only submit when they win. **All on-chain "randomness" is predictable.**

**Secure:**
```rust
// Use Switchboard VRF or another verifiable randomness oracle
let vrf_result = VrfAccountData::new(&ctx.accounts.vrf)?.get_result()?;
require!(!vrf_result.eq(&[0u8; 32]), VrfNotResolved);
let winner_index = u64::from_le_bytes(vrf_result[..8].try_into()?) % total_entries;
```

---

## V94 - Off-Chain Validation Reliance

**Detect:** On-chain instruction handler that assumes client/frontend enforces invariants. Missing on-chain validation for constraints documented only in SDK/frontend code. Comments like "validated by client" or "frontend checks this".

**Vulnerable:**
```rust
pub fn create_order(ctx: Context<CreateOrder>, price: u64, amount: u64) -> Result<()> {
    // "Frontend validates price is within 5% of oracle" - NOT enforced on-chain
    order.price = price;
    order.amount = amount;
    // Attacker calls instruction directly with arbitrary price
}
```

**Exploit:** Attacker bypasses frontend, calls the instruction directly via CLI/SDK with any parameters. All "client-side validation" is meaningless for security.

**Secure:**
```rust
let oracle_price = get_oracle_price(&ctx.accounts.oracle)?;
require!(
    price >= oracle_price * 95 / 100 && price <= oracle_price * 105 / 100,
    PriceOutOfRange
);
```

---

## V95 - Rent Exemption Not Enforced in Bonding Curves

**Detect:** Bonding curve or treasury account that can have SOL withdrawn below rent-exempt minimum. `transfer` of SOL without checking remaining balance covers rent. Manual lamport manipulation without rent check.

**Vulnerable:**
```rust
pub fn sell(ctx: Context<Sell>, amount: u64) -> Result<()> {
    let sol_out = calculate_sell_price(amount, &ctx.accounts.bonding_curve)?;
    **ctx.accounts.bonding_curve.lamports.borrow_mut() -= sol_out;
    **ctx.accounts.seller.lamports.borrow_mut() += sol_out;
    // No check: bonding_curve may drop below rent-exempt minimum
    // Runtime garbage-collects the account → all state lost
}
```

**Exploit:** **Pump Science (M-02)** - sell operation could drain bonding curve below rent-exempt threshold. Account gets garbage collected, destroying the entire curve state and locking remaining tokens.

**Secure:**
```rust
let rent = Rent::get()?;
let min_balance = rent.minimum_balance(ctx.accounts.bonding_curve.data_len());
require!(
    ctx.accounts.bonding_curve.lamports() - sol_out >= min_balance,
    InsufficientRentBalance
);
```

---

## V96 - Transfer Hook Validation - Fake Mint with Malicious Hook

**Detect:** Protocol accepting arbitrary Token-2022 mints with transfer hooks without validating the hook program. Mint's `TransferHook` extension points to attacker-controlled program. Missing `transferring` flag check in hook program.

**Vulnerable:**
```rust
// Protocol accepts any Token-2022 mint without checking transfer hook program
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    transfer_checked(cpi_ctx, amount, decimals)?;
    // Mint's transfer hook program could:
    // 1. Revert selectively (DoS withdrawals but not deposits)
    // 2. Execute arbitrary logic on every transfer
}
```

**Exploit:** Attacker creates mint with transfer hook pointing to malicious program. Deposits succeed, but hook program reverts on withdrawals → funds locked. Or: hook program has side effects that manipulate other protocol state.

**Secure:**
```rust
// Allowlist specific mints, or validate the hook program
if let Ok(hook) = mint_state.get_extension::<TransferHook>() {
    let hook_program = Option::<Pubkey>::from(hook.program_id);
    require!(
        hook_program.is_none() || ALLOWED_HOOK_PROGRAMS.contains(&hook_program.unwrap()),
        UnsupportedTransferHook
    );
}
```

---

## V97 - `.unwrap()` Panic in Instruction Handler

**Detect:** `.unwrap()`, `.expect()`, `panic!()`, `unreachable!()`, `todo!()` in any instruction handler code path. `array[index]` without bounds check (panics on out-of-bounds).

**Vulnerable:**
```rust
pub fn process(ctx: Context<Process>, index: u8) -> Result<()> {
    let item = ctx.accounts.pool.items[index as usize];  // panics if index >= items.len()
    let value = some_option.unwrap();  // panics if None
    let parsed: u64 = data.try_into().unwrap();  // panics on bad data
}
```

**Exploit:** Attacker passes crafted input that triggers `.unwrap()` on `None`/`Err` or out-of-bounds array access. Transaction panics with uninformative error. If this is a critical path (e.g., liquidation, withdrawal), it becomes a DoS vector.

**Secure:**
```rust
let item = ctx.accounts.pool.items
    .get(index as usize)
    .ok_or(ErrorCode::IndexOutOfBounds)?;
let value = some_option.ok_or(ErrorCode::MissingValue)?;
let parsed: u64 = data.try_into().map_err(|_| ErrorCode::InvalidData)?;
```

---

## V98 - Missing Input Amount Validation

**Detect:** Instruction accepting `amount: u64` without checking `amount > 0` or `amount <= MAX`. Zero-amount operations that trigger state changes (events, nonce increments, share minting) without economic commitment.

**Vulnerable:**
```rust
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    // No minimum check - amount = 0 is accepted
    transfer(cpi_ctx, amount)?;  // transfers 0 tokens - succeeds
    user.deposit_count += 1;     // state changed without economic action
    emit!(DepositEvent { amount });  // pollutes event log
}
```

**Exploit:** Zero-amount deposits to: trigger side effects, manipulate counters, spam events, or satisfy "has deposited" requirements without committing funds. `u64::MAX` amounts overflow subsequent calculations.

**Secure:**
```rust
require!(amount > 0, ZeroAmount);
require!(amount <= MAX_DEPOSIT, AmountTooLarge);
```

---

## V99 - Program Upgrade Authority Not Secured

**Detect:** Upgradeable program where upgrade authority is a single EOA (not multisig, not governance, not `None`). `BPFUpgradeableLoader` programdata account with single-key authority.

**Vulnerable:**
```rust
// solana program deploy --upgrade-authority <single-hot-wallet>
// Attacker compromises this one key → deploys malicious code → drains all TVL
```

**Exploit:** Highest-impact vector for upgradeable programs. Single compromised key replaces entire program logic. All funds in program-owned PDAs immediately drainable.

**Secure:**
```rust
// Option 1: Make immutable
solana program set-upgrade-authority <PROGRAM_ID> --final

// Option 2: Multisig/governance authority
solana program set-upgrade-authority <PROGRAM_ID> --new-upgrade-authority <MULTISIG_ADDRESS>

// Option 3: Timelock - users can exit before upgrade takes effect
```

---

## V100 - Interest Accrual During Protocol Pause

**Detect:** `paused` flag that gates deposits/withdrawals but not interest/fee accumulation functions. `accrue_interest()` callable (or auto-triggered) while paused. No pause check on time-dependent state updates.

**Vulnerable:**
```rust
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    require!(!pool.paused, ProtocolPaused);  // gated
    accrue_interest(&mut pool)?;  // interest updated on deposit
    // ...
}

pub fn accrue_interest(pool: &mut Pool) -> Result<()> {
    // NOT gated by pause - interest accrues during pause
    let elapsed = clock.unix_timestamp - pool.last_accrual;
    pool.accrued_interest += pool.total_borrows * rate * elapsed;
    pool.last_accrual = clock.unix_timestamp;
}
```

**Exploit:** Protocol pauses for emergency (exploit, upgrade). Interest keeps accruing. When unpaused, borrowers face unexpected interest charges. Positions liquidated immediately due to interest accumulated during pause. Lenders may also be affected if utilization-based rates spike.

**Secure:**
```rust
pub fn accrue_interest(pool: &mut Pool) -> Result<()> {
    if pool.paused {
        pool.last_accrual = clock.unix_timestamp;  // skip accrual window
        return Ok(());
    }
    // Normal accrual logic
}
// Or: cap accrued interest to pre-pause levels on unpause
```
