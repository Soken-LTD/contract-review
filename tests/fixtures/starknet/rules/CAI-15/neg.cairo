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
            let n = self.nonce.read();
            let msg = poseidon_hash_span(array![h, n, get_tx_info().chain_id].span());
            assert(check_ecdsa_signature(msg, self.key.read(), r, s), 'sig');
            self.nonce.write(n + 1);
        }
    }
}
