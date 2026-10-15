#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[abi(embed_v0)]
    impl I of super::IC<ContractState> {
        fn walk(ref self: ContractState, n: u32) {
            let mut i: u32 = n;
            while i != 0 {
                i -= 1;
            }
        }
    }
}
