// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import {Test, console} from "forge-std/Test.sol";
import {Counter} from "pinned/src/Counter.sol";
interface IWETH9 { function deposit() external payable; function balanceOf(address) external view returns (uint256); }
contract WethDepositTest is Test {
    IWETH9 constant WETH = IWETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    function test_depositCreditsBalance() public {
        vm.deal(address(this), 1 ether);
        uint256 before = WETH.balanceOf(address(this));
        WETH.deposit{value: 1 ether}();
        console.log("deposited", uint256(1 ether));
        assertEq(WETH.balanceOf(address(this)), before + 1 ether, "balance after deposit");
        Counter c = new Counter(); c.inc(); assertEq(c.n(), 1);
    }
}
