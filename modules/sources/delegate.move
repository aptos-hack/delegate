module delegate_addr::delegate {
    use std::bcs::to_bytes;
    use std::option;
    use std::option::Option;
    use aptos_framework::account::{Self};
    use aptos_framework::event::{Self, EventHandle};

    use aptos_std::table::{Self, Table};
    use aptos_std::aptos_hash;
    use aptos_std::vector;
    use std::signer;
    use std::signer::address_of;
    use std::string::{Self, String};
    use aptos_std::string_utils::to_string;
    use aptos_framework::object;
    use aptos_framework::object::{Object, ConstructorRef};
    use aptos_token_objects::collection;
    use aptos_token_objects::collection::{Collection};
    use aptos_token_objects::royalty;
    use aptos_token_objects::royalty::Royalty;
    use aptos_token_objects::token;
    use aptos_token_objects::token::Token;

    /// Constants
    const DELEGATE_ALL_TYPES: u8 = 0;
    const DELEGATE_WALLET: u8 = 1;
    const DELEGATE_MODULE: u8 = 2;
    const DELEGATE_TOKEN: u8 = 3;

    /// Errors
    const VAULT_HAS_BEEN_PUBLISHED: u64 = 0;
    const DELEGATE_HAS_BEEN_PUBLISHED: u64 = 1;

    const DEFAULT_NIL_ADDRESS: address = @0x0;



    struct DelegationInfo has store, copy, drop {
        // keccak256 hash of vault, delegate address
        delegatation_hash: String,

        // DELEGATE_ALL, DELEGATE_MODULE or DELEGATE_TOKEN
        delegatation_type: u8,

        // Address of the token module, or nil if delegating for all modules
        token: Option<Object<Token>>,

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

    /**
     * Delegate vault to delegate address for a delegate type
     */
    fun delegate_for_type(vault: &signer, delegate: address, enabled: bool, delegate_type: u8, token: Option<Object<Token>>) acquires VaultDelegations, DelegateTable {
        let vault_address = signer::address_of(vault);
        let nft_token = option::to_vec(token);

        let token_addr: Option<address>;

        // If empty, must be DELEGATE_ALL
        if (vector::is_empty<Object<Token>>(&nft_token)) {
            assert!(delegate_type == DELEGATE_WALLET, 0x50001);
            token_addr = option::none<address>();
        } else {
            // If not empty, must be DELEGATE_TOKEN
            assert!(delegate_type == DELEGATE_TOKEN, 0x50002);
            let nft_token_obj = vector::borrow(&nft_token, 0);
            token_addr = option::some(object::object_address(nft_token_obj));
        };

        let delegation_hash: vector<u8> = compute_hash(vault_address, delegate, delegate_type, token_addr);

        set_delegation_values(vault_address, delegate, delegation_hash, delegate_type, enabled, token);

        let delegation_info_table_ref = borrow_global_mut<VaultDelegations>(vault_address);
        event::emit_event( &mut delegation_info_table_ref.delegate_for_all_event, DelegateForAllEvent {
            vault: vault_address,
            delegate,
            enabled,
        });
    }

    /**
     * Delegate vault to delegate address for all modules and tokens
     */
    public entry fun delegate_for_wallet(vault: &signer, delegate: address, enabled: bool) acquires VaultDelegations, DelegateTable {
        delegate_for_type(vault, delegate, enabled, DELEGATE_WALLET, option::none<Object<Token>>());
    }

    /**
     * Delegate vault to delegate address for non-fungible token
     */
    public entry fun delegate_for_token(vault: &signer, delegate: address, enabled: bool, token: Object<Token>) acquires VaultDelegations, DelegateTable {
        // object::object_from_constructor_ref()
        // object::generate_extend_ref(// constructor_ref)
        delegate_for_type(vault, delegate, enabled, DELEGATE_TOKEN, option::some(token));
    }

    // Internal function to get delegation info by delegate address & delegation type
    fun get_delegation_by_delegation_type(delegate: address, delegate_type: u8): vector<DelegationInfo> acquires DelegateTable {
        // delegation hashes for a given delegate
        let delegate_table_ref = borrow_global<DelegateTable>(delegate);
        let potential_delegation_hashes = &delegate_table_ref.delegation_hashes;

        let delegation_info_list: vector<DelegationInfo> = vector::empty<DelegationInfo>();

        let idx = 0;
        while (idx < vector::length(potential_delegation_hashes)) {
            let delegation_hash = *(vector::borrow(potential_delegation_hashes, idx));
            let delegation_info = table::borrow(&delegate_table_ref.delegation_hash_to_info, delegation_hash);

            if (delegation_info.delegatation_hash == delegation_hash) {
                // For now we only support DELEGATE_ALL
                if (delegation_info.delegatation_type == delegate_type) {
                    vector::push_back(&mut delegation_info_list, *delegation_info);
                }
            };

            idx = idx + 1;
        };

        delegation_info_list
    }

    #[view]
    public fun get_delegation_by_delegate_for_wallet(delegate: address): vector<DelegationInfo> acquires DelegateTable {
        get_delegation_by_delegation_type(delegate, DELEGATE_WALLET)
    }

    #[view]
    public fun get_delegation_by_delegate_for_token(delegate: address): vector<DelegationInfo> acquires DelegateTable {
        get_delegation_by_delegation_type(delegate, DELEGATE_TOKEN)
    }

    /**
     * Concatenate vault and delegate address and compute hash with keccak256 algorithm
     */
    fun compute_hash(vault: address, delegate: address, delegation_type: u8, token: Option<address>): vector<u8> {
        let input_addr_vec: vector<address> = vector<address>[vault, delegate];

        // If token is not empty, add it to the input address vector
        if (option::is_some(&token)) {
            let token_vec = option::to_vec(token);
            let token_obj = vector::borrow(&token_vec, 0);
            vector::push_back(&mut input_addr_vec, *token_obj);
        };

        let input_addr_bytes = to_bytes(&input_addr_vec);
        vector::push_back(&mut input_addr_bytes, delegation_type);

        aptos_hash::keccak256(input_addr_bytes)
    }

    fun set_delegation_values(
        vault: address,
        delegate: address,
        delegation_hash: vector<u8>,
        delegation_type: u8,
        enabled: bool,
        token: Option<Object<Token>>,
    ) acquires VaultDelegations, DelegateTable {
        let vault_delegations = borrow_global_mut<VaultDelegations>(vault);
        let delegate_table = borrow_global_mut<DelegateTable>(delegate);

        let delegation_hash_str = to_string(&delegation_hash);

        if (enabled) {
            let delegation_info = DelegationInfo {
                delegatation_hash: delegation_hash_str,
                vault,
                delegatation_type: delegation_type,
                delegate,
                token,
            };

            // Add delegation info into the list
            vector::push_back(&mut vault_delegations.delegations, delegation_info);

            // Add delegation address mapping to delegation hash
            let delegation_hashes_ref = &mut delegate_table.delegation_hashes;
            vector::push_back(delegation_hashes_ref, delegation_hash_str);

            // Add delegation hash mapping to delegation info
            table::upsert(&mut delegate_table.delegation_hash_to_info, delegation_hash_str, delegation_info);
        } else {
            // Remove delegation info from the list
            let delegations = &mut vault_delegations.delegations;
            let delegations_idx = 0;

            // Start with a value that is out of bound, to make it easy to check
            let idx_to_remove = vector::length(delegations);

            while (delegations_idx < vector::length(delegations)) {
                let delegation_info = vector::borrow(delegations, delegations_idx);
                if (delegation_info.delegatation_hash == delegation_hash_str) {
                    idx_to_remove = delegations_idx;
                    break
                };

                delegations_idx = delegations_idx + 1;
            };

            if (idx_to_remove < vector::length(delegations)) {
                vector::remove(delegations, idx_to_remove);
            };
            // endregion //

            // Remove delegation address mapping to delegation hash
            let delegation_hashes_ref = &mut delegate_table.delegation_hashes;
            let idx = 0;
            let delegation_to_hash_idx = vector::length(delegation_hashes_ref);

            while (idx < vector::length(delegation_hashes_ref)) {
                let delegation_hash = vector::borrow(delegation_hashes_ref, idx);
                if (*delegation_hash == delegation_hash_str) {
                    delegation_to_hash_idx = idx;
                    break
                };

                idx = idx + 1;
            };

            if (delegation_to_hash_idx < vector::length(delegations)) {
                vector::remove(delegations, delegation_to_hash_idx);
            };
            // endregion //

            // Remove delegation hash mapping to delegation info
            table::remove(&mut delegate_table.delegation_hash_to_info, delegation_hash_str);
        }
    }

    #[test_only]
    fun set_up_test(vault: &signer, delegate: &signer) {
        account::create_account_for_test(signer::address_of(vault));

        // register vault and delegates
        register_delegate(delegate);
        register_vault(vault);

        account::create_account_for_test(signer::address_of(delegate));
    }

    #[test_only]
    fun set_up_test_multiple_delegates(
        vault: &signer, delegate1: &signer, delegate2: &signer, delegate3: &signer) {
        account::create_account_for_test(signer::address_of(vault));

        // register vault and delegates
        register_vault(vault);

        register_delegate(delegate1);
        register_delegate(delegate2);
        register_delegate(delegate3);

        // TODO: put this into a loop
        account::create_account_for_test(signer::address_of(delegate1));
        account::create_account_for_test(signer::address_of(delegate2));
        account::create_account_for_test(signer::address_of(delegate3));
    }

    #[test_only]
    fun set_up_test_multiple_vaults(vault1: &signer, vault2: &signer, vault3: &signer, delegate: &signer) {
        // TODO: put this in a loop
        account::create_account_for_test(signer::address_of(vault1));
        account::create_account_for_test(signer::address_of(vault2));
        account::create_account_for_test(signer::address_of(vault3));

        // register vault and delegates
        register_vault(vault1);
        register_vault(vault2);
        register_vault(vault3);

        register_delegate(delegate);

        account::create_account_for_test(signer::address_of(delegate));
    }

    #[test_only]
    fun set_up_test_multi_vaults_multi_delegates(
        vault1: &signer, vault2: &signer, vault3: &signer, delegate1: &signer, delegate2: &signer, delegate3: &signer) {

        // TODO: put this in a loop
        account::create_account_for_test(signer::address_of(vault1));
        account::create_account_for_test(signer::address_of(vault2));
        account::create_account_for_test(signer::address_of(vault3));

        // register vault and delegates
        register_delegate(delegate1);
        register_delegate(delegate2);
        register_delegate(delegate3);

        register_vault(vault1);
        register_vault(vault2);
        register_vault(vault3);

        // TODO: put this into a loop
        account::create_account_for_test(signer::address_of(delegate1));
        account::create_account_for_test(signer::address_of(delegate2));
        account::create_account_for_test(signer::address_of(delegate3));
    }

    #[test_only]
    fun create_collection_helper(creator: &signer, collection_name: String, max_supply: u64) {
        collection::create_fixed_collection(
            creator,
            string::utf8(b"collection description"),
            max_supply,
            collection_name,
            option::none(),
            string::utf8(b"collection uri"),
        );
    }

    inline fun create_common(
        constructor_ref: &ConstructorRef,
        creator_address: address,
        collection_name: String,
        description: String,
        name: String,
        royalty: Option<Royalty>,
        uri: String,
    ): ConstructorRef {
        let object_signer = object::generate_signer(constructor_ref);

        let collection_addr = collection::create_collection_address(&creator_address, &collection_name);
        object::address_to_object<Collection>(collection_addr);

        let token = token::create(
            &object_signer,
            collection_name,
            description,
            name,
            royalty,
            uri
        );

        if (option::is_some(&royalty)) {
            royalty::init(constructor_ref, option::extract(&mut royalty))
        };

        token
    }


    #[test_only]
    fun create_named_token(
        creator: &signer,
        collection_name: String,
        description: String,
        name: String,
        royalty: Option<Royalty>,
        uri: String,
    ): ConstructorRef {
        let creator_address = signer::address_of(creator);
        let constructor_ref = object::create_named_object(creator, vector::empty());
        create_common(&constructor_ref, creator_address, collection_name, description, name, royalty, uri);
        constructor_ref
    }

    #[test_only]
    fun create_test_nft(creator: &signer): Object<Token> {
        let collection_name = string::utf8(b"collection name");
        let token_name = string::utf8(b"token name");

        create_collection_helper(creator, collection_name, 1);
        let constructor_ref = create_named_token(
            creator,
            collection_name,
            string::utf8(b"token description"),
            token_name,
            option::some(royalty::create(1, 1, signer::address_of(creator))),
            string::utf8(b"token uri"),
        );
        object::object_from_constructor_ref<Token>(&constructor_ref)

    }

    #[test(vault = @0xa, delegate = @0xb)]
    fun test_delegate_for_all(vault: &signer, delegate: &signer) acquires DelegateTable, VaultDelegations {
        set_up_test(vault,  delegate);

        assert!(is_delegate_registered(signer::address_of(delegate)) == true, 0x50001);
        assert!(is_vault_registered(signer::address_of(vault)) == true, 0x50002);
        delegate_for_wallet(vault, signer::address_of(delegate), true);
    }

    #[test(vault = @0xa, delegate = @0xb)]
    fun test_single_vault_delegate_read(vault: &signer, delegate: &signer) acquires DelegateTable, VaultDelegations {
        set_up_test(vault,  delegate);

        assert!(is_delegate_registered(signer::address_of(delegate)) == true, 0x50001);
        assert!(is_vault_registered(signer::address_of(vault)) == true, 0x50002);

        // Delegate vault to delegate address for all modules and tokens
        delegate_for_wallet(vault, signer::address_of(delegate), true);

        // Read delegation info
        let delegation_info_list = get_delegation_by_delegate_for_wallet(signer::address_of(delegate));
        assert!(vector::length(&delegation_info_list) == 1, 0x80001);

        let delegation_info = vector::borrow(&delegation_info_list, 0);
        assert!(delegation_info.delegatation_type == DELEGATE_WALLET, 0x80002);
        assert!(delegation_info.vault == signer::address_of(vault), 0x80003);
        assert!(delegation_info.delegate == signer::address_of(delegate), 0x80004);
    }

    // Single vault, delegating multiple delegates
    #[test(vault = @0xa, delegate1 = @0xb, delegate2 = @0xc, delegate3 = @0xd)]
    fun test_single_vault_multiple_delegates_read(vault: &signer, delegate1: &signer, delegate2: &signer, delegate3: &signer) acquires DelegateTable, VaultDelegations {
        set_up_test_multiple_delegates(vault,  delegate1, delegate2, delegate3);

        assert!(is_delegate_registered(signer::address_of(delegate1)) == true, 0x50001);
        assert!(is_delegate_registered(signer::address_of(delegate2)) == true, 0x50002);
        assert!(is_delegate_registered(signer::address_of(delegate3)) == true, 0x50003);
        assert!(is_vault_registered(signer::address_of(vault)) == true, 0x50004);

        // Delegate vault to delegate address for all modules and tokens
        delegate_for_wallet(vault, signer::address_of(delegate1), true);
        delegate_for_wallet(vault, signer::address_of(delegate2), true);
        delegate_for_wallet(vault, signer::address_of(delegate3), true);

        // Read delegate1 info
        let delegate1_info_list = get_delegation_by_delegate_for_wallet(signer::address_of(delegate1));
        assert!(vector::length(&delegate1_info_list) == 1, 0x80001);

        let delegate1_info = vector::borrow(&delegate1_info_list, 0);
        assert!(delegate1_info.delegatation_type == DELEGATE_WALLET, 0x80002);
        assert!(delegate1_info.vault == signer::address_of(vault), 0x80003);
        assert!(delegate1_info.delegate == signer::address_of(delegate1), 0x80004);

        // Read delegate2 info
        let delegate2_info_list = get_delegation_by_delegate_for_wallet(signer::address_of(delegate2));
        assert!(vector::length(&delegate2_info_list) == 1, 0x80005);

        let delegate2_info = vector::borrow(&delegate2_info_list, 0);
        assert!(delegate2_info.delegatation_type == DELEGATE_WALLET, 0x80006);
        assert!(delegate2_info.vault == signer::address_of(vault), 0x80007);
        assert!(delegate2_info.delegate == signer::address_of(delegate2), 0x80008);

        // Read delegate3 info
        let delegate3_info_list = get_delegation_by_delegate_for_wallet(signer::address_of(delegate3));
        assert!(vector::length(&delegate3_info_list) == 1, 0x80009);

        let delegate3_info = vector::borrow(&delegate3_info_list, 0);
        assert!(delegate3_info.delegatation_type == DELEGATE_WALLET, 0x80010);
        assert!(delegate3_info.vault == signer::address_of(vault), 0x80011);
        assert!(delegate3_info.delegate == signer::address_of(delegate3), 0x80012);
    }

    // Multiple vaults, delegating single delegate
    #[test(vault1 = @0xa, vault2 = @0xb, vault3 = @0xc, delegate = @0xd)]
    fun test_multi_vaults_single_delegate_read(vault1: &signer, vault2: &signer, vault3: &signer, delegate: &signer) acquires DelegateTable, VaultDelegations {
        set_up_test_multiple_vaults(vault1, vault2, vault3,  delegate);

        assert!(is_vault_registered(signer::address_of(vault1)) == true, 0x50001);
        assert!(is_vault_registered(signer::address_of(vault2)) == true, 0x50002);
        assert!(is_vault_registered(signer::address_of(vault3)) == true, 0x50003);
        assert!(is_delegate_registered(signer::address_of(delegate)) == true, 0x50004);

        // Delegate vault to delegate address for all modules and tokens
        delegate_for_wallet(vault1, signer::address_of(delegate), true);
        delegate_for_wallet(vault2, signer::address_of(delegate), true);
        delegate_for_wallet(vault3, signer::address_of(delegate), true);

        // Read delegate info
        let delegate_info_list = get_delegation_by_delegate_for_wallet(signer::address_of(delegate));
        assert!(vector::length(&delegate_info_list) == 3, 0x80001);

        let delegate_info1 = vector::borrow(&delegate_info_list, 0);
        assert!(delegate_info1.delegatation_type == DELEGATE_WALLET, 0x80002);
        assert!(delegate_info1.vault == signer::address_of(vault1), 0x80003);
        assert!(delegate_info1.delegate == signer::address_of(delegate), 0x80004);

        let delegate_info2 = vector::borrow(&delegate_info_list, 1);
        assert!(delegate_info2.delegatation_type == DELEGATE_WALLET, 0x80005);
        assert!(delegate_info2.vault == signer::address_of(vault2), 0x80006);
        assert!(delegate_info2.delegate == signer::address_of(delegate), 0x80007);

        let delegate_info3 = vector::borrow(&delegate_info_list, 2);
        assert!(delegate_info3.delegatation_type == DELEGATE_WALLET, 0x80008);
        assert!(delegate_info3.vault == signer::address_of(vault3), 0x80009);
        assert!(delegate_info3.delegate == signer::address_of(delegate), 0x80010);
    }

    #[test(account = @0xa)]
    fun test_bulk_register(account: &signer)  {
        account::create_account_for_test(signer::address_of(account));

        bulk_regsiter(account);

        assert!(is_vault_registered(signer::address_of(account)) == true, 0x50001);
        assert!(is_delegate_registered(signer::address_of(account)) == true, 0x50002);
    }

    // Multiple vaults, delegating multiple delegates
    #[test(vault1 = @0xa, vault2 = @0xb, vault3 = @0xc, delegate1 = @0xd, delegate2 = @0xe, delegate3 = @0xf)]
    fun test_multi_vaults_multi_delegates(vault1: &signer, vault2: &signer, vault3: &signer, delegate1: &signer, delegate2: &signer, delegate3: &signer) acquires DelegateTable, VaultDelegations {
        set_up_test_multi_vaults_multi_delegates(vault1, vault2, vault3,  delegate1, delegate2, delegate3);

        // Delegate vault to delegate address for all modules and tokens
        delegate_for_wallet(vault1, signer::address_of(delegate1), true);
        delegate_for_wallet(vault1, signer::address_of(delegate2), true);

        delegate_for_wallet(vault2, signer::address_of(delegate2), true);

        delegate_for_wallet(vault3, signer::address_of(delegate1), true);
        delegate_for_wallet(vault3, signer::address_of(delegate2), true);
        delegate_for_wallet(vault3, signer::address_of(delegate3), true);

        // Read delegate1 info list
        let delegate1_info_list = get_delegation_by_delegate_for_wallet(signer::address_of(delegate1));
        assert!(vector::length(&delegate1_info_list) == 2, 0x80001);

        let delegate1_info1 = vector::borrow(&delegate1_info_list, 0);
        assert!(delegate1_info1.delegatation_type == DELEGATE_WALLET, 0x80002);
        assert!(delegate1_info1.vault == signer::address_of(vault1), 0x80003);
        assert!(delegate1_info1.delegate == signer::address_of(delegate1), 0x80004);

        let delegate1_info2 = vector::borrow(&delegate1_info_list, 1);
        assert!(delegate1_info2.delegatation_type == DELEGATE_WALLET, 0x80005);
        assert!(delegate1_info2.vault == signer::address_of(vault3), 0x80006);
        assert!(delegate1_info2.delegate == signer::address_of(delegate1), 0x80007);

        // Read delegate2 info list
        let delegate2_info_list = get_delegation_by_delegate_for_wallet(signer::address_of(delegate2));
        assert!(vector::length(&delegate2_info_list) == 3, 0x80008);

        let delegate2_info1 = vector::borrow(&delegate2_info_list, 0);
        assert!(delegate2_info1.delegatation_type == DELEGATE_WALLET, 0x80009);
        assert!(delegate2_info1.vault == signer::address_of(vault1), 0x80010);
        assert!(delegate2_info1.delegate == signer::address_of(delegate2), 0x80011);

        let delegate2_info2 = vector::borrow(&delegate2_info_list, 1);
        assert!(delegate2_info2.delegatation_type == DELEGATE_WALLET, 0x80012);
        assert!(delegate2_info2.vault == signer::address_of(vault2), 0x80013);
        assert!(delegate2_info2.delegate == signer::address_of(delegate2), 0x80014);

        let delegate2_info3 = vector::borrow(&delegate2_info_list, 2);
        assert!(delegate2_info3.delegatation_type == DELEGATE_WALLET, 0x80015);
        assert!(delegate2_info3.vault == signer::address_of(vault3), 0x80016);
        assert!(delegate2_info3.delegate == signer::address_of(delegate2), 0x80017);

        // Read delegate3 info list
        let delegate3_info_list = get_delegation_by_delegate_for_wallet(signer::address_of(delegate3));
        assert!(vector::length(&delegate3_info_list) == 1, 0x80018);

        let delegate3_info = vector::borrow(&delegate3_info_list, 0);
        assert!(delegate3_info.delegatation_type == DELEGATE_WALLET, 0x80019);
        assert!(delegate3_info.vault == signer::address_of(vault3), 0x80020);
        assert!(delegate3_info.delegate == signer::address_of(delegate3), 0x80021);
    }

    // Multiple vaults, delegating multiple delegates, for multiple delegate types
    #[test(vault1 = @0xa, vault2 = @0xb, vault3 = @0xc, delegate1 = @0xd, delegate2 = @0xe, delegate3 = @0xf)]
    fun test_multi_vaults_multi_delegates_multitype(vault1: &signer, vault2: &signer, vault3: &signer, delegate1: &signer, delegate2: &signer, delegate3: &signer) acquires DelegateTable, VaultDelegations {
        set_up_test_multi_vaults_multi_delegates(vault1, vault2, vault3,  delegate1, delegate2, delegate3);

        // Delegate vault to delegate address for all modules and tokens
        delegate_for_wallet(vault1, signer::address_of(delegate1), true);
        delegate_for_wallet(vault3, signer::address_of(delegate1), true);

        let object_token = create_test_nft(vault1);

        delegate_for_token(vault1, signer::address_of(delegate2), true, object_token);
        delegate_for_wallet(vault2, signer::address_of(delegate2), true);
        delegate_for_wallet(vault3, signer::address_of(delegate2), true);

        delegate_for_wallet(vault3, signer::address_of(delegate3), true);

        // Read delegate1 info list
        let delegate1_info_list = get_delegation_by_delegate_for_wallet(signer::address_of(delegate1));
        assert!(vector::length(&delegate1_info_list) == 2, 0x80001);

        let delegate1_info1 = vector::borrow(&delegate1_info_list, 0);
        assert!(delegate1_info1.delegatation_type == DELEGATE_WALLET, 0x80002);
        assert!(delegate1_info1.vault == signer::address_of(vault1), 0x80003);
        assert!(delegate1_info1.delegate == signer::address_of(delegate1), 0x80004);

        let delegate1_info2 = vector::borrow(&delegate1_info_list, 1);
        assert!(delegate1_info2.delegatation_type == DELEGATE_WALLET, 0x80005);
        assert!(delegate1_info2.vault == signer::address_of(vault3), 0x80006);
        assert!(delegate1_info2.delegate == signer::address_of(delegate1), 0x80007);

        // Read delegate2 info list
        let delegate2_info_list = get_delegation_by_delegate_for_wallet(signer::address_of(delegate2));
        assert!(vector::length(&delegate2_info_list) == 2, 0x80008);

        let delegate2_info1 = vector::borrow(&delegate2_info_list, 0);
        assert!(delegate2_info1.delegatation_type == DELEGATE_WALLET, 0x80009);
        // assert!(delegate2_info1.vault == signer::address_of(vault3), 0x80010);
        assert!(delegate2_info1.delegate == signer::address_of(delegate2), 0x80011);

        let delegate2_info2 = vector::borrow(&delegate2_info_list, 1);
        assert!(delegate2_info2.delegatation_type == DELEGATE_WALLET, 0x80012);
        assert!(delegate2_info2.vault == signer::address_of(vault2), 0x80013);
        assert!(delegate2_info2.delegate == signer::address_of(delegate2), 0x80014);

        let delegate2_info3 = vector::borrow(&delegate2_info_list, 2);
        assert!(delegate2_info3.delegatation_type == DELEGATE_TOKEN, 0x80015);
        assert!(delegate2_info3.vault == signer::address_of(vault1), 0x80016);
        assert!(delegate2_info3.delegate == signer::address_of(delegate2), 0x80017);

        // Read delegate3 info list
        let delegate3_info_list = get_delegation_by_delegate_for_wallet(signer::address_of(delegate3));
        assert!(vector::length(&delegate3_info_list) == 1, 0x80018);

        let delegate3_info = vector::borrow(&delegate3_info_list, 0);
        assert!(delegate3_info.delegatation_type == DELEGATE_WALLET, 0x80019);
        assert!(delegate3_info.vault == signer::address_of(vault3), 0x80020);
        assert!(delegate3_info.delegate == signer::address_of(delegate3), 0x80021);

        // Read delegate2 info list, for token
        let delegate2_token_info_list = get_delegation_by_delegate_for_token(signer::address_of(delegate2));
        assert!(vector::length(&delegate2_token_info_list) == 1, 0x80022);

        let delegate2_token_info = vector::borrow(&delegate2_token_info_list, 0);
        assert!(delegate2_token_info.delegatation_type == DELEGATE_TOKEN, 0x80023);
        assert!(delegate2_token_info.vault == signer::address_of(vault1), 0x80024);
        assert!(delegate2_token_info.delegate == signer::address_of(delegate2), 0x80025);

    }

    // Create delegate, then remove delegate, should be empty

}
