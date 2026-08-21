// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title OpenDrainWallet
/// @notice INTENTIONAL VULNERABILITY for auditor fixtures.
///         `withdrawAll` has no access control — anyone can drain the contract.
contract OpenDrainWallet {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    receive() external payable {}

    function withdrawAll(address payable to) external {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "send failed");
    }
}
