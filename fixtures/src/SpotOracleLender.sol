// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IUniswapV2Pair {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}

/// @title SpotOracleLender
/// @notice INTENTIONAL VULNERABILITY for auditor fixtures.
///         Collateral is priced from a Uniswap V2 spot `getReserves()` call, which is
///         trivial to manipulate with a large swap on the same pair.
contract SpotOracleLender {
    IERC20 public immutable weth;
    IERC20 public immutable usdc;
    IUniswapV2Pair public immutable pair;

    uint256 public constant LTV_BPS = 8000;

    mapping(address => uint256) public collateralWeth;
    mapping(address => uint256) public debtUsdc;

    constructor(address weth_, address usdc_, address pair_) {
        weth = IERC20(weth_);
        usdc = IERC20(usdc_);
        pair = IUniswapV2Pair(pair_);
    }

    function depositCollateral(uint256 amount) external {
        require(weth.transferFrom(msg.sender, address(this), amount), "transferFrom");
        collateralWeth[msg.sender] += amount;
    }

    /// @return USDC (6 decimals) per 1 WETH (1e18 wei), using spot reserves.
    function wethPriceUsdc() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        address token0 = pair.token0();
        if (token0 == address(usdc)) {
            return (uint256(reserve0) * 1e18) / uint256(reserve1);
        }
        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }

    function maxBorrow(address user) public view returns (uint256) {
        uint256 valueUsdc = (collateralWeth[user] * wethPriceUsdc()) / 1e18;
        return (valueUsdc * LTV_BPS) / 10_000;
    }

    function borrow(uint256 usdcAmount) external {
        uint256 newDebt = debtUsdc[msg.sender] + usdcAmount;
        require(newDebt <= maxBorrow(msg.sender), "exceeds LTV");
        debtUsdc[msg.sender] = newDebt;
        require(usdc.transfer(msg.sender, usdcAmount), "transfer");
    }
}
