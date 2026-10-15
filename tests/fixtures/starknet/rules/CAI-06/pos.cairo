#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn upgrade(ref self: ContractState, h: ClassHash) {
            replace_class_syscall(h).unwrap_syscall();
        }
    }
}
