#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn initialize(ref self: ContractState, o: ContractAddress) {
            assert(!self.initialized.read(), 'done');
            self.initialized.write(true);
            self.owner.write(o);
        }
    }
}
