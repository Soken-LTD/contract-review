#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn raw(ref self: ContractState, key: felt252, v: felt252) {
            storage_write_syscall(0, storage_address_from_base(storage_base_address_from_felt252(key)), v).unwrap_syscall();
        }
    }
}
