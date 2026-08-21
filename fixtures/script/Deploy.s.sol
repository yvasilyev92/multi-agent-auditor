// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "forge-std/console2.sol";

import "../src/ReentrancyVault.sol";
import "../src/OpenDrainWallet.sol";
import "../src/SpotOracleLender.sol";

/// @notice Deploy fixture contracts onto a local Anvil mainnet fork.
/// @dev Run against Anvil only (not live Ethereum):
///      forge script script/Deploy.s.sol:DeployScript --rpc-url http://127.0.0.1:PORT --broadcast --private-key $PRIVATE_KEY
contract DeployScript is Script {
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    // Uniswap V2 USDC/WETH
    address constant PAIR = 0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc;

    function run() public {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address account = vm.addr(privateKey);
        console2.log("Deployer:", account);

        vm.startBroadcast(privateKey);

        ReentrancyVault vault = new ReentrancyVault();
        vault.deposit{value: 10 ether}();
        console2.log("ReentrancyVault:", address(vault));

        OpenDrainWallet wallet = new OpenDrainWallet{value: 5 ether}();
        console2.log("OpenDrainWallet:", address(wallet));

        SpotOracleLender lender = new SpotOracleLender(WETH, USDC, PAIR);
        console2.log("SpotOracleLender:", address(lender));

        vm.stopBroadcast();
    }

    function test() public {}
}
