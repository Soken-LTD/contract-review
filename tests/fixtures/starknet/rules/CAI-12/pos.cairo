#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn pay(ref self: ContractState, t: ContractAddress, to: ContractAddress) {
            IERC20Dispatcher { contract_address: t }.transfer(to, 1);
        }
    }
}
