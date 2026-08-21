// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "forge-std/console2.sol";

import "../src/ReentrancyVault.sol";

/// @title Deploy ReentrancyVault to Ethereum mainnet
/// @notice Empty intentional-vuln contract so the auditor can fetch verified source
///         from Etherscan. Do not deposit ETH or call withdraw on live mainnet.
///         PoCs run only against a local fork of this address.
///
/// Simulate (no tx):
///   set -a && source ../.env && set +a
///   forge script script/DeployReentrancyVault.s.sol:DeployReentrancyVault --rpc-url "$INFURA_URL"
///
/// Broadcast + verify:
///   forge script script/DeployReentrancyVault.s.sol:DeployReentrancyVault \
///     --rpc-url "$INFURA_URL" --broadcast --verify \
///     --etherscan-api-key "$ETHERSCAN_API_KEY" -vvvv
contract DeployReentrancyVault is Script {
    function run() public {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(privateKey);

        console2.log("Chain id:", block.chainid);
        console2.log("Deployer:", deployer);
        console2.log("Deployer ETH:", deployer.balance);

        require(block.chainid == 1, "refusing to run off Ethereum mainnet (chainid != 1)");
        require(deployer.balance >= 0.005 ether, "deployer ETH too low for gas");

        vm.startBroadcast(privateKey);
        ReentrancyVault vault = new ReentrancyVault();
        vm.stopBroadcast();

        console2.log("ReentrancyVault:", address(vault));
        console2.log("Paste this address into the Streamlit auditor after Etherscan verifies source.");
    }

    function test() public {}
}
