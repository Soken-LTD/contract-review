#[starknet::component]
pub mod Comp {
    #[storage]
    pub struct Storage {
        pub Comp_balance: u256,
    }
}
#[starknet::contract]
mod C {
    #[storage]
    struct Storage {
        balance: u256,
        #[substorage(v0)]
        comp: super::Comp::Storage,
    }
}
