/// Tests for CatoVault recursive covenant implementation

use crate::vault::{
    VaultState, VaultConfig, VaultWitness, CatoVaultTrait,
    execute_vault_script, simulate_vault_lifecycle
};
use crate::vm::{ScriptVMTrait, sha256};

// ============================================
// VaultConfig Tests
// ============================================

fn create_test_config() -> VaultConfig {
    let mut cold_key: ByteArray = "";
    let mut hot_key: ByteArray = "";
    let mut recovery_key: ByteArray = "";

    // 32-byte dummy keys
    let mut i: u32 = 0;
    while i < 32 {
        cold_key.append_byte(0x01);
        hot_key.append_byte(0x02);
        recovery_key.append_byte(0x03);
        i += 1;
    };

    VaultConfig {
        timelock_blocks: 144,  // ~1 day
        cold_pubkey: cold_key,
        hot_pubkey: hot_key,
        recovery_pubkey: recovery_key,
        amount_sats: 100000000,  // 1 BTC
    }
}

#[test]
fn test_vault_script_generation() {
    let config = create_test_config();
    let script = CatoVaultTrait::generate_script(@config);

    // Script should be non-empty
    assert!(script.len() > 0, "Vault script should be generated");

    // Script should contain OP_OVER (0x78), OP_CAT (0x7e), OP_SHA256 (0xa8)
    // These are the core recursive covenant opcodes
    let mut has_over = false;
    let mut has_cat = false;
    let mut has_sha256 = false;

    let mut i: u32 = 0;
    while i < script.len() {
        let op = *script.at(i);
        if op == 0x78 { has_over = true; }
        if op == 0x7e { has_cat = true; }
        if op == 0xa8 { has_sha256 = true; }
        i += 1;
    };

    assert!(has_over, "Script should contain OP_OVER");
    assert!(has_cat, "Script should contain OP_CAT");
    assert!(has_sha256, "Script should contain OP_SHA256");
}

// ============================================
// State Transition Tests
// ============================================

#[test]
fn test_cold_to_pending_transition() {
    let config = create_test_config();

    // Create witness for Cold -> Pending
    let script = CatoVaultTrait::generate_script(@config);
    let mut output_script: ByteArray = "";
    let mut i: u32 = 0;
    while i < script.len() {
        output_script.append_byte(*script.at(i));
        i += 1;
    };

    let mut sig: ByteArray = "";
    sig.append_byte(0x30); // DER signature prefix
    let mut j: u32 = 0;
    while j < 63 {
        sig.append_byte(0xaa);
        j += 1;
    };

    let witness = VaultWitness {
        signature: sig,
        current_height: 100,
        pending_since: 0,
        next_state: VaultState::Pending,
        output_script: output_script,
    };

    let result = CatoVaultTrait::verify_transition(
        @config,
        VaultState::Cold,
        @witness
    );

    assert!(result.is_ok(), "Cold -> Pending should be valid");
    let new_state = result.unwrap();
    assert!(new_state == VaultState::Pending, "New state should be Pending");
}

#[test]
fn test_pending_to_hot_after_timelock() {
    let config = create_test_config();

    let script = CatoVaultTrait::generate_script(@config);
    let mut output_script: ByteArray = "";
    let mut i: u32 = 0;
    while i < script.len() {
        output_script.append_byte(*script.at(i));
        i += 1;
    };

    let mut sig: ByteArray = "";
    sig.append_byte(0x30);
    let mut j: u32 = 0;
    while j < 63 {
        sig.append_byte(0xbb);
        j += 1;
    };

    // Timelock has passed: pending_since=100, current=250, timelock=144
    // 250 - 100 = 150 > 144 blocks
    let witness = VaultWitness {
        signature: sig,
        current_height: 250,
        pending_since: 100,
        next_state: VaultState::Hot,
        output_script: output_script,
    };

    let result = CatoVaultTrait::verify_transition(
        @config,
        VaultState::Pending,
        @witness
    );

    assert!(result.is_ok(), "Pending -> Hot should be valid after timelock");
}

#[test]
fn test_pending_to_hot_before_timelock_fails() {
    let config = create_test_config();

    let script = CatoVaultTrait::generate_script(@config);
    let mut output_script: ByteArray = "";
    let mut i: u32 = 0;
    while i < script.len() {
        output_script.append_byte(*script.at(i));
        i += 1;
    };

    let mut sig: ByteArray = "";
    sig.append_byte(0x30);
    let mut j: u32 = 0;
    while j < 63 {
        sig.append_byte(0xcc);
        j += 1;
    };

    // Timelock NOT passed: pending_since=100, current=200, timelock=144
    // 200 - 100 = 100 < 144 blocks
    let witness = VaultWitness {
        signature: sig,
        current_height: 200,
        pending_since: 100,
        next_state: VaultState::Hot,
        output_script: output_script,
    };

    let result = CatoVaultTrait::verify_transition(
        @config,
        VaultState::Pending,
        @witness
    );

    assert!(result.is_err(), "Pending -> Hot should fail before timelock");
}

#[test]
fn test_pending_to_cancelled() {
    let config = create_test_config();

    let script = CatoVaultTrait::generate_script(@config);
    let mut output_script: ByteArray = "";
    let mut i: u32 = 0;
    while i < script.len() {
        output_script.append_byte(*script.at(i));
        i += 1;
    };

    let mut sig: ByteArray = "";
    sig.append_byte(0x30);
    let mut j: u32 = 0;
    while j < 63 {
        sig.append_byte(0xdd);
        j += 1;
    };

    // Cancel can happen immediately (no timelock required)
    let witness = VaultWitness {
        signature: sig,
        current_height: 101,
        pending_since: 100,
        next_state: VaultState::Cancelled,
        output_script: output_script,
    };

    let result = CatoVaultTrait::verify_transition(
        @config,
        VaultState::Pending,
        @witness
    );

    assert!(result.is_ok(), "Pending -> Cancelled should be valid immediately");
}

#[test]
fn test_invalid_cold_to_hot() {
    let config = create_test_config();

    let script = CatoVaultTrait::generate_script(@config);
    let mut output_script: ByteArray = "";
    let mut i: u32 = 0;
    while i < script.len() {
        output_script.append_byte(*script.at(i));
        i += 1;
    };

    let mut sig: ByteArray = "";
    sig.append_byte(0x30);
    let mut j: u32 = 0;
    while j < 63 {
        sig.append_byte(0xee);
        j += 1;
    };

    // Invalid: can't go directly from Cold to Hot
    let witness = VaultWitness {
        signature: sig,
        current_height: 100,
        pending_since: 0,
        next_state: VaultState::Hot,
        output_script: output_script,
    };

    let result = CatoVaultTrait::verify_transition(
        @config,
        VaultState::Cold,
        @witness
    );

    assert!(result.is_err(), "Cold -> Hot should be invalid");
}

// ============================================
// Witness Script Generation Tests
// ============================================

#[test]
fn test_witness_script_cold_to_pending() {
    let config = create_test_config();
    let witness_script = CatoVaultTrait::build_witness_script(
        @config,
        VaultState::Cold,
        VaultState::Pending
    );

    assert!(witness_script.len() > 0, "Witness script should be generated");

    // Should contain OP_CAT (0x7e) and OP_SHA256 (0xa8)
    let mut has_cat = false;
    let mut has_sha256 = false;

    let mut i: u32 = 0;
    while i < witness_script.len() {
        let op = *witness_script.at(i);
        if op == 0x7e { has_cat = true; }
        if op == 0xa8 { has_sha256 = true; }
        i += 1;
    };

    assert!(has_cat, "Witness script should contain OP_CAT");
    assert!(has_sha256, "Witness script should contain OP_SHA256");
}

#[test]
fn test_witness_script_pending_to_hot_has_timelock() {
    let config = create_test_config();
    let witness_script = CatoVaultTrait::build_witness_script(
        @config,
        VaultState::Pending,
        VaultState::Hot
    );

    assert!(witness_script.len() > 0, "Witness script should be generated");

    // Should contain OP_CHECKLOCKTIMEVERIFY (0xb1)
    let mut has_cltv = false;

    let mut i: u32 = 0;
    while i < witness_script.len() {
        let op = *witness_script.at(i);
        if op == 0xb1 { has_cltv = true; }
        i += 1;
    };

    assert!(has_cltv, "Pending->Hot witness should contain CHECKLOCKTIMEVERIFY");
}

// ============================================
// Lifecycle Simulation Test
// ============================================

#[test]
fn test_vault_lifecycle_simulation() {
    let results = simulate_vault_lifecycle();

    // Should return 4 results (script lengths for different stages)
    assert!(results.len() == 4, "Should have 4 results");

    // All script lengths should be positive (felt252 != 0)
    assert!(*results.at(0) != 0, "Main vault script should have length > 0");
    assert!(*results.at(1) != 0, "Pending witness script should have length > 0");
    assert!(*results.at(2) != 0, "Hot witness script should have length > 0");
    assert!(*results.at(3) != 0, "Cancel witness script should have length > 0");
}

// ============================================
// Recursive Covenant Pattern Test
// ============================================

#[test]
fn test_recursive_covenant_hash_verification() {
    // This tests the core recursive covenant pattern:
    // The output script hash must match the input script hash

    let config = create_test_config();
    let script = CatoVaultTrait::generate_script(@config);

    // Convert script to ByteArray for hashing
    let mut script_bytes: ByteArray = "";
    let mut i: u32 = 0;
    while i < script.len() {
        script_bytes.append_byte(*script.at(i));
        i += 1;
    };

    // Hash the script
    let script_hash = sha256(@script_bytes);

    // The hash should be 32 bytes
    assert!(script_hash.len() == 32, "Script hash should be 32 bytes");

    // Hashing the same script again should produce the same hash
    let script_hash_2 = sha256(@script_bytes);
    assert!(script_hash.len() == script_hash_2.len(), "Hashes should have same length");

    let mut same = true;
    let mut j: u32 = 0;
    while j < script_hash.len() {
        if script_hash.at(j).unwrap() != script_hash_2.at(j).unwrap() {
            same = false;
        }
        j += 1;
    };
    assert!(same, "Same script should produce same hash");
}

// ============================================
// Execute Vault Script Test
// ============================================

#[test]
fn test_execute_simple_vault_script() {
    // Test a simple vault-like script: CAT SHA256 DROP OP_1
    // This mimics the recursive pattern without the full verification

    let mut stack: Array<ByteArray> = array![];

    // Push two data elements to concatenate
    let mut data1: ByteArray = "";
    data1.append_byte(0xde);
    data1.append_byte(0xad);
    stack.append(data1);

    let mut data2: ByteArray = "";
    data2.append_byte(0xbe);
    data2.append_byte(0xef);
    stack.append(data2);

    // Script: CAT SHA256 DROP OP_1
    let script: Array<u8> = array![
        0x7e,  // OP_CAT
        0xa8,  // OP_SHA256
        0x75,  // OP_DROP
        0x51   // OP_1
    ];

    let result = execute_vault_script(script, stack);
    assert!(result.is_ok(), "Simple vault script should execute");
    assert!(result.unwrap(), "Script should return true");
}
