#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn pull(ref self: ContractState, t: ContractAddress, f: ContractAddress) {
            let ok = IERC20Dispatcher { contract_address: t }.transfer_from(f, get_contract_address(), 1);
            assert(ok, 'x');
        }
    }
}
