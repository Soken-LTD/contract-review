#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn sum(self: @ContractState, n: u64) -> u256 {
            let mut s = 0;
            for i in 0..n {
                s += i.into();
            }
            s
        }
    }
}
