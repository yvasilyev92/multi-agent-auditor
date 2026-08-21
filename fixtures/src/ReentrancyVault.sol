// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ReentrancyVault
/// @notice INTENTIONAL VULNERABILITY for auditor fixtures.
///         `withdraw` sends ETH before zeroing the caller's balance (classic reentrancy).
contract ReentrancyVault {
    mapping(address => uint256) public balances;

    constructor() payable {}

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
}
