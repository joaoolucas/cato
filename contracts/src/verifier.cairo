/// Cato On-Chain Verifier
///
/// This contract verifies STARK proofs of Bitcoin Script execution on Starknet.
/// It interfaces with the Integrity Verifier (formerly SHARP) to validate that
/// Cato correctly executed Bitcoin Script with OP_CAT.
///
/// Verification Flow:
/// 1. User executes Bitcoin Script in Cato (off-chain)
/// 2. STARK proof is generated from execution trace
/// 3. Proof is submitted to SHARP/Integrity Verifier
/// 4. This contract checks the fact registry to confirm verification
///
/// The "fact" is a hash of (program_hash, output_hash) that proves:
/// - The specific Cato program was executed
/// - It produced the claimed outputs
/// - The execution was valid (STARK proof verified)

use starknet::ContractAddress;

/// Herodotus FactRegistry types
#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct VerifierConfiguration {
    pub layout: felt252,
    pub hasher: felt252,
    pub stone_version: felt252,
    pub memory_verification: felt252,
}

#[derive(Drop, Copy, Serde)]
pub struct VerificationListElement {
    pub verification_hash: felt252,
    pub security_bits: u32,
    pub verifier_config: VerifierConfiguration,
}

#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct Verification {
    pub fact_hash: felt252,
    pub security_bits: u32,
    pub verifier_config: VerifierConfiguration,
}

/// Herodotus FactRegistry interface
#[starknet::interface]
pub trait IFactRegistry<TContractState> {
    fn get_all_verifications_for_fact_hash(
        self: @TContractState, fact_hash: felt252
    ) -> Array<VerificationListElement>;

    fn get_verification(
        self: @TContractState, verification_hash: felt252
    ) -> Option<Verification>;
}

/// Cato Verifier storage
#[starknet::interface]
pub trait ICatoVerifier<TContractState> {
    /// Verify a Bitcoin Script execution proof
    /// Returns true if the proof is valid and registered in the fact registry
    fn verify_bitcoin_script(
        ref self: TContractState,
        program_hash: felt252,
        output_hash: felt252,
    ) -> bool;

    /// Verify a vault state transition
    fn verify_vault_transition(
        ref self: TContractState,
        vault_id: felt252,
        from_state: u8,
        to_state: u8,
        proof_fact: felt252,
    ) -> bool;

    /// Register a new verified proof (called after SHARP verification)
    fn register_proof(
        ref self: TContractState,
        fact_hash: felt252,
        program_hash: felt252,
        output_hash: felt252,
    );

    /// Check if a fact has been verified
    fn is_fact_verified(self: @TContractState, fact_hash: felt252) -> bool;

    /// Get the Cato program hash (identifies the Bitcoin Script VM)
    fn get_cato_program_hash(self: @TContractState) -> felt252;

    /// Get the FactRegistry address
    fn get_fact_registry(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod CatoVerifier {
    use starknet::{ContractAddress, get_caller_address, get_block_number};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::poseidon::poseidon_hash_span;
    use super::{IFactRegistryDispatcher, IFactRegistryDispatcherTrait};

    #[storage]
    struct Storage {
        /// Address of the Herodotus FactRegistry contract
        fact_registry: ContractAddress,
        /// The Cato program hash (identifies our Bitcoin Script VM)
        cato_program_hash: felt252,
        /// Mapping of fact_hash -> verified status
        verified_facts: Map<felt252, bool>,
        /// Mapping of fact_hash -> program_hash
        fact_program_hash: Map<felt252, felt252>,
        /// Mapping of fact_hash -> output_hash
        fact_output_hash: Map<felt252, felt252>,
        /// Owner for administrative functions
        owner: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        BitcoinScriptVerified: BitcoinScriptVerified,
        VaultStateTransition: VaultStateTransition,
        ProofRegistered: ProofRegistered,
    }

    #[derive(Drop, starknet::Event)]
    pub struct BitcoinScriptVerified {
        #[key]
        pub tx_hash: felt252,
        pub script_hash: felt252,
        pub result: bool,
        pub verifier: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VaultStateTransition {
        #[key]
        pub vault_id: felt252,
        pub from_state: u8,
        pub to_state: u8,
        pub block_height: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProofRegistered {
        #[key]
        pub fact_hash: felt252,
        pub program_hash: felt252,
        pub output_hash: felt252,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        fact_registry: ContractAddress,
        cato_program_hash: felt252,
        owner: ContractAddress,
    ) {
        self.fact_registry.write(fact_registry);
        self.cato_program_hash.write(cato_program_hash);
        self.owner.write(owner);
    }

    #[abi(embed_v0)]
    impl CatoVerifierImpl of super::ICatoVerifier<ContractState> {
        /// Verify a Bitcoin Script execution by checking the fact registry
        fn verify_bitcoin_script(
            ref self: ContractState,
            program_hash: felt252,
            output_hash: felt252,
        ) -> bool {
            // Compute the fact hash: hash(program_hash, output_hash)
            let fact_hash = compute_fact_hash(program_hash, output_hash);

            // Check if already verified locally
            if self.verified_facts.read(fact_hash) {
                return true;
            }

            // Check the Herodotus FactRegistry
            let registry = IFactRegistryDispatcher {
                contract_address: self.fact_registry.read()
            };

            // Fact is valid if there are any verifications for it
            let verifications = registry.get_all_verifications_for_fact_hash(fact_hash);
            let is_valid = verifications.len() > 0;

            if is_valid {
                // Cache the verification result
                self.verified_facts.write(fact_hash, true);
                self.fact_program_hash.write(fact_hash, program_hash);
                self.fact_output_hash.write(fact_hash, output_hash);

                // Emit event
                self.emit(BitcoinScriptVerified {
                    tx_hash: output_hash,  // Use output_hash as tx identifier
                    script_hash: program_hash,
                    result: true,
                    verifier: get_caller_address(),
                });
            }

            is_valid
        }

        /// Verify a vault state transition proof
        fn verify_vault_transition(
            ref self: ContractState,
            vault_id: felt252,
            from_state: u8,
            to_state: u8,
            proof_fact: felt252,
        ) -> bool {
            // Verify the proof exists in the fact registry
            let registry = IFactRegistryDispatcher {
                contract_address: self.fact_registry.read()
            };

            let verifications = registry.get_all_verifications_for_fact_hash(proof_fact);
            let is_valid = verifications.len() > 0;

            if is_valid {
                // Emit vault transition event
                self.emit(VaultStateTransition {
                    vault_id,
                    from_state,
                    to_state,
                    block_height: get_block_number(),
                });
            }

            is_valid
        }

        /// Register a proof after Herodotus verification
        fn register_proof(
            ref self: ContractState,
            fact_hash: felt252,
            program_hash: felt252,
            output_hash: felt252,
        ) {
            // Verify fact hash matches
            let computed_fact = compute_fact_hash(program_hash, output_hash);
            assert(fact_hash == computed_fact, 'Invalid fact hash');

            // Check with Herodotus FactRegistry
            let registry = IFactRegistryDispatcher {
                contract_address: self.fact_registry.read()
            };
            let verifications = registry.get_all_verifications_for_fact_hash(fact_hash);
            assert(verifications.len() > 0, 'Fact not verified');

            // Store the verified fact
            self.verified_facts.write(fact_hash, true);
            self.fact_program_hash.write(fact_hash, program_hash);
            self.fact_output_hash.write(fact_hash, output_hash);

            self.emit(ProofRegistered {
                fact_hash,
                program_hash,
                output_hash,
            });
        }

        /// Check if a fact has been verified
        fn is_fact_verified(self: @ContractState, fact_hash: felt252) -> bool {
            // Check local cache first
            if self.verified_facts.read(fact_hash) {
                return true;
            }

            // Check Herodotus FactRegistry
            let registry = IFactRegistryDispatcher {
                contract_address: self.fact_registry.read()
            };
            let verifications = registry.get_all_verifications_for_fact_hash(fact_hash);
            verifications.len() > 0
        }

        /// Get the Cato program hash
        fn get_cato_program_hash(self: @ContractState) -> felt252 {
            self.cato_program_hash.read()
        }

        /// Get the FactRegistry address
        fn get_fact_registry(self: @ContractState) -> ContractAddress {
            self.fact_registry.read()
        }
    }

    /// Compute the fact hash from program and output hashes
    fn compute_fact_hash(program_hash: felt252, output_hash: felt252) -> felt252 {
        poseidon_hash_span(array![program_hash, output_hash].span())
    }
}

/// Vault states for on-chain tracking
pub mod vault_states {
    pub const COLD: u8 = 0;
    pub const PENDING: u8 = 1;
    pub const HOT: u8 = 2;
    pub const CANCELLED: u8 = 3;
}

/// Helper functions for proof submission
pub mod proof_utils {
    use core::poseidon::poseidon_hash_span;

    /// Compute the program hash from bytecode
    pub fn compute_program_hash(bytecode: Span<felt252>) -> felt252 {
        poseidon_hash_span(bytecode)
    }

    /// Compute the output hash from execution results
    pub fn compute_output_hash(outputs: Span<felt252>) -> felt252 {
        poseidon_hash_span(outputs)
    }

    /// Compute the fact hash that will be registered with SHARP
    pub fn compute_fact_hash(program_hash: felt252, output_hash: felt252) -> felt252 {
        poseidon_hash_span(array![program_hash, output_hash].span())
    }
}
