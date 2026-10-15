#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn exec(ref self: ContractState, h: felt252, r: felt252, s: felt252) {
            assert(check_ecdsa_signature(h, self.key.read(), r, s), 'sig');
            self.value.write(h);
        }
    }
}
