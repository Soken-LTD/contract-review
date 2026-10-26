// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Shares {
    uint256 internal _totalSupply;
    mapping(address => uint256) internal _balances;

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function _mint(address to, uint256 amount) internal {
        _totalSupply += amount;
        _balances[to] += amount;
    }

    function _burn(address from, uint256 amount) internal {
        _balances[from] -= amount;
        _totalSupply -= amount;
    }
}

/// A snapshot written on every deposit and never reset when supply returns to zero.
contract StaleVault is Shares {
    uint256 public totalAssets;
    uint256 public lastSharePrice;

    function deposit(uint256 assets) external {
        uint256 supply = totalSupply();
        uint256 shares;
        if (supply == 0) {
            shares = assets;
        } else {
            require(assets * 1e18 / supply >= lastSharePrice, "price");
            shares = assets * supply / totalAssets;
        }
        totalAssets += assets;
        _mint(msg.sender, shares);
        lastSharePrice = totalAssets * 1e18 / totalSupply();
    }

    function redeem(uint256 shares) external {
        uint256 assets = shares * totalAssets / totalSupply();
        _burn(msg.sender, shares);
        totalAssets -= assets;
    }
}

/// The same snapshot, reset when the last share is burned: no stale signal.
contract ResetVault is Shares {
    uint256 public totalAssets;
    uint256 public lastSharePrice;

    function deposit(uint256 assets) external {
        uint256 shares = totalSupply() == 0 ? assets : assets * totalSupply() / totalAssets;
        totalAssets += assets;
        _mint(msg.sender, shares);
        lastSharePrice = totalAssets * 1e18 / totalSupply();
    }

    function redeem(uint256 shares) external {
        uint256 assets = shares * totalAssets / totalSupply();
        _burn(msg.sender, shares);
        totalAssets -= assets;
        if (totalSupply() == 0) {
            lastSharePrice = 0;
        }
    }
}

/// Synthetix-style rewards: the clock moves while nothing is staked.
contract Rewards {
    uint256 public totalStaked;
    uint256 public rewardRate;
    uint256 public rewardPerTokenStored;
    uint256 public lastUpdateTime;
    address public owner;
    uint256 public feeBps;
    mapping(address => uint256) public stakes;

    modifier updateReward() {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = block.timestamp;
        _;
    }

    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) {
            return rewardPerTokenStored;
        }
        return rewardPerTokenStored + (block.timestamp - lastUpdateTime) * rewardRate * 1e18 / totalStaked;
    }

    function stake(uint256 amount) external updateReward {
        totalStaked += amount;
        stakes[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external updateReward {
        totalStaked -= amount;
        stakes[msg.sender] -= amount;
    }

    /// Admin configuration: never a lifecycle signal.
    function setFee(uint256 bps) external {
        require(msg.sender == owner, "owner");
        feeBps = bps;
    }

    /// Division by the population with no zero check on the path.
    function sharePerStake(uint256 amount) external view returns (uint256) {
        return amount * 1e18 / totalStaked;
    }
}
