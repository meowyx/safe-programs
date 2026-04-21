# Attack Vectors Reference - Additional Vectors (5/5)

> Part 5 · Vectors 101–105
> Covers: CPI ownership reassignment, unsafe deserialization, orphan accounts, partial discriminators, Token-2022 dynamic sizing

---

## V101 - Account Ownership Reassignment via CPI

**Detect:** `system_instruction::assign` or `system_instruction::allocate` in CPI where target account's signer privilege is forwarded from caller.

**Vulnerable:**
```rust
pub fn exploit(accounts: &[AccountInfo]) -> ProgramResult {
    let user_account = &accounts[0];  // signer privilege forwarded from caller
    let ix = system_instruction::assign(user_account.key, &malicious_program_id);
    invoke(&ix, &[user_account.clone()])?;  // steals ownership
    Ok(())
}
```

**Exploit:** Attacker's program receives forwarded signer privilege and reassigns account ownership. Attacker can then modify account data freely.

**Secure:**
```rust
// Never forward user signer to untrusted programs (V32)
// Post-CPI: require!(*account.owner == expected_program_id, OwnershipChanged);
```

---

## V102 - Unsafe Deserialization Without Input Length Validation

**Detect:** `BorshDeserialize::deserialize` or `try_from_slice` on user-provided data without `data.len()` validation. Trailing bytes silently ignored.

**Vulnerable:**
```rust
let input = MyInput::try_from_slice(data)?;
// Undersized: panic. Oversized: trailing bytes ignored
```

**Secure:**
```rust
require!(data.len() == EXPECTED_SIZE, InvalidInputLength);
let input = MyInput::try_from_slice(data)?;
```

---

## V103 - Orphan Account from Parent-Child Lifecycle

**Detect:** Parent account closeable while child accounts still reference it. No `active_children` counter or cascade-close logic.

**Vulnerable:**
```rust
pub fn close_pool(ctx: Context<ClosePool>) -> Result<()> {
    // UserStake accounts with seeds = [b"stake", pool.key()] still exist
    // Users can't unstake - pool gone, has_one = pool fails
    Ok(())
}
```

**Exploit:** Parent closed, child accounts orphaned. User funds locked permanently.

**Secure:**
```rust
require!(pool.active_positions == 0, PoolHasActivePositions);
```

---

## V104 - Partial Discriminator / Selector Matching

**Detect:** Instruction dispatch using single-byte discriminator (`data[0]`). Account type validation using fewer than 8 bytes.

**Vulnerable:**
```rust
match instruction_data[0] {
    0 => process_initialize(accounts, &instruction_data[1..]),
    1 => process_deposit(accounts, &instruction_data[1..]),
    // Only 256 values - collision risk
}
```

**Exploit:** Attacker crafts accounts/inputs passing partial type check with different data layout - type confusion (V3).

**Secure:**
```rust
let discriminator = &account_data[..8];
require!(discriminator == Vault::DISCRIMINATOR, WrongAccountType);
```

---

## V105 - Dynamic Token-2022 Account Size via Extensions

**Detect:** Hardcoded `space = TokenAccount::LEN` (165 bytes) for Token-2022 accounts. Missing extension size calculation.

**Vulnerable:**
```rust
#[account(init, payer = user, space = TokenAccount::LEN)]
pub vault_token: InterfaceAccount<'info, TokenAccount>,
// Token-2022 with extensions needs more space - creation fails
```

**Exploit:** Cannot create token accounts for mints with extensions. DoS on deposits/withdrawals.

**Secure:**
```rust
let space = ExtensionType::try_calculate_account_len::<Token2022Account>(&required_extensions)?;
```
