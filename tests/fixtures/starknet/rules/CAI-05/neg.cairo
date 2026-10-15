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
            self.value.write(v);
        }
    }
}
