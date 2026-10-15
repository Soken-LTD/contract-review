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
            self.owner.write(o);
        }
    }
}
