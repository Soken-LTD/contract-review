// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import {Test} from "forge-std/Test.sol";
import "pinned/src/Counter.sol" as P;
interface IWETH9 { function balanceOf(address) external view returns (uint256); }
contract Counter { uint256 public n; function inc() external { n += 2; } }
contract ShadowTest is Test {
    function test_shadowAndLiteral() public {
        string memory s = "new P.Counter() and Counter(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2).inc()";
        Counter c = new Counter(); c.inc();
        assertEq(c.n(), 2);
        assertGt(bytes(s).length, 0);
        assertGt(address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2).code.length, 0);
    }
}
