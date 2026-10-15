#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn act(ref self: ContractState) {
            assert(get_caller_address() == self.owner.read(), 'owner');
            self.value.write(1);
        }
    }
}
