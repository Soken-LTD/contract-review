#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn make(ref self: ContractState, h: ClassHash, salt: felt252) {
            deploy_syscall(h, salt, array![].span(), true).unwrap_syscall();
        }
    }
}
