module delegate_addr::delegate {
    use std::bcs::to_bytes;
    use aptos_framework::account::{Self};
    use aptos_framework::event::{Self, EventHandle};

    use aptos_std::table::{Self, Table};
    use aptos_std::aptos_hash;
    use aptos_std::vector;
    use std::signer;
    use std::signer::address_of;
    use std::string::{String};
    use aptos_std::string_utils::to_string;

    /// Constants
    const DELEGATE_ALL: u8 = 0;
    const DELEGATE_MODULE: u8 = 1;
    const DELEGATE_TOKEN: u8 = 2;

    /// Errors
    const VAULT_HAS_BEEN_PUBLISHED: u64 = 0;
    const DELEGATE_HAS_BEEN_PUBLISHED: u64 = 1;

    struct DelegationInfo has store, copy, drop {
        // keccak256 hash of vault and delegate address
        delegatation_hash: String,

        // DELEGATE_ALL, DELEGATE_MODULE or DELEGATE_TOKEN
        delegatation_type: u8,

        // Vault that delegates
        vault: address,

        // Delegated address
        delegate: address,
    }

    struct VaultDelegations has key {
        // Vault -> DelegationInfo
        delegations: vector<DelegationInfo>,

        // Events
        delegate_for_all_event: EventHandle<DelegateForAllEvent>,
    }

    struct DelegateTable has key {
        // Delegate address -> Delegation Hash
        delegation_hashes: vector<String>,

        // Delegation Hash -> DelegationInfo
        delegation_hash_to_info: Table<String, DelegationInfo>,
    }


    // Events
    struct DelegateForAllEvent has drop, store {
        vault: address,
        delegate: address,
        enabled: bool,
    }

    public entry fun register_vault(vault: &signer) {
        if (!exists<VaultDelegations>(address_of(vault))) {
            move_to(vault, VaultDelegations {
                delegations: vector::empty<DelegationInfo>(),
                delegate_for_all_event: account::new_event_handle<DelegateForAllEvent>(vault),
            });
        }
    }

    #[view]
    public fun is_vault_registered(vault_address: address): bool {
        exists<VaultDelegations>(vault_address)
    }

    public entry fun register_delegate(delegate: &signer) {
        if (!exists<DelegateTable>(address_of(delegate))) {
            move_to(delegate, DelegateTable {
                delegation_hashes: vector::empty<String>(),
                delegation_hash_to_info: table::new<String, DelegationInfo>(),
            });
        }
    }

    #[view]
    public fun is_delegate_registered(delegate_address: address): bool {
        exists<DelegateTable>(delegate_address)
    }

    // Bulk register vault and delegate
    public entry fun bulk_regsiter(vault: &signer) {
        register_vault(vault);
        register_delegate(vault);
    }
}