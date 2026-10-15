#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn pack(ref self: ContractState, a: felt252, b: felt252) {
            assert(b < 0x100000000, 'b');
            self.value.write(a * 0x100000000 + b);
        }
    }
}
