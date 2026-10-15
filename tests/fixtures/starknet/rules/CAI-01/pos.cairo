#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn bump(ref self: ContractState, by: felt252) {
            self.value.write(self.value.read() + by);
        }
    }
}
