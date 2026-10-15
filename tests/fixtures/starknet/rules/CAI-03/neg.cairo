#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn to_l1(ref self: ContractState, a: felt252) {
            let e: EthAddress = a.try_into().unwrap();
            self.e.write(e);
        }
    }
}
