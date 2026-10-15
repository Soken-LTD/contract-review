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
            if get_caller_address().is_zero() {
                self.value.write(1);
            }
        }
    }
}
