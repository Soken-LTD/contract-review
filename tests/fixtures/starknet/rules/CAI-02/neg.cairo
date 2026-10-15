#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
    }
    #[l1_handler]
    fn on_l1(ref self: ContractState, from_address: felt252, v: felt252) {
        assert(from_address == self.l1.read(), 'bad sender');
        self.value.write(v);
    }
}
