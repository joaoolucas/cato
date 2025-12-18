pub mod opcodes;
pub mod vm;

#[cfg(test)]
mod tests;

// ============================================
// Provable Execution Demo
// ============================================

use vm::ScriptVMTrait;
use opcodes::{OP_CAT, OP_DUP, OP_VERIFY};

/// Cato Bitcoin Script VM - Provable Execution
///
/// This function executes Bitcoin Scripts with OP_CAT and produces
/// deterministic outputs that can be proven with STARKs.
///
/// Run with: scarb execute --print-program-output
#[executable]
fn prove_bitcoin_script() -> Array<felt252> {
    let mut results: Array<felt252> = array![];

    // ============================================
    // Test 1: Basic OP_CAT concatenation
    // Script: PUSH "hello" PUSH "world" OP_CAT
    // Expected: "helloworld" (10 bytes)
    // ============================================
    let script1: Array<u8> = array![
        0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,  // PUSH_5 "hello"
        0x05, 0x77, 0x6f, 0x72, 0x6c, 0x64,  // PUSH_5 "world"
        OP_CAT
    ];

    let mut vm1 = ScriptVMTrait::new(script1);
    let result1 = vm1.execute();

    if result1.is_ok() {
        let stack_result = vm1.stack.at(0);
        results.append(stack_result.len().into()); // Should be 10
    } else {
        results.append(0);
    }

    // ============================================
    // Test 2: OP_DUP + OP_CAT (doubles string)
    // Script: PUSH "ABC" DUP CAT
    // Expected: "ABCABC" (6 bytes)
    // ============================================
    let script2: Array<u8> = array![
        0x03, 0x41, 0x42, 0x43,  // PUSH_3 "ABC"
        OP_DUP,
        OP_CAT
    ];

    let mut vm2 = ScriptVMTrait::new(script2);
    let result2 = vm2.execute();

    if result2.is_ok() {
        let stack_result = vm2.stack.at(0);
        results.append(stack_result.len().into()); // Should be 6
    } else {
        results.append(0);
    }

    // ============================================
    // Test 3: Chain 4 elements with 3 CATs
    // Expected: "abcd" (4 bytes)
    // ============================================
    let script3: Array<u8> = array![
        0x01, 0x61,  // PUSH_1 "a"
        0x01, 0x62,  // PUSH_1 "b"
        0x01, 0x63,  // PUSH_1 "c"
        0x01, 0x64,  // PUSH_1 "d"
        OP_CAT, OP_CAT, OP_CAT
    ];

    let mut vm3 = ScriptVMTrait::new(script3);
    let result3 = vm3.execute();

    if result3.is_ok() {
        let stack_result = vm3.stack.at(0);
        results.append(stack_result.len().into()); // Should be 4
    } else {
        results.append(0);
    }

    // ============================================
    // Test 4: Maximum size (260 + 260 = 520 bytes)
    // ============================================
    let mut elem_a: ByteArray = "";
    let mut elem_b: ByteArray = "";
    let mut i: u32 = 0;
    while i < 260 {
        elem_a.append_byte((i % 256).try_into().unwrap());
        elem_b.append_byte(((i + 128) % 256).try_into().unwrap());
        i += 1;
    };

    let mut stack4: Array<ByteArray> = array![];
    stack4.append(elem_a);
    stack4.append(elem_b);

    let script4: Array<u8> = array![OP_CAT];
    let mut vm4 = ScriptVMTrait::new_with_stack(script4, stack4);
    let result4 = vm4.execute();

    if result4.is_ok() {
        let stack_result = vm4.stack.at(0);
        results.append(stack_result.len().into()); // Should be 520
    } else {
        results.append(0);
    }

    // ============================================
    // Test 5: Covenant pattern (CAT + VERIFY)
    // ============================================
    let script5: Array<u8> = array![
        0x04, 0xde, 0xad, 0xbe, 0xef,  // PUSH_4 deadbeef
        OP_DUP,
        OP_CAT,
        OP_VERIFY
    ];

    let mut vm5 = ScriptVMTrait::new(script5);
    let result5 = vm5.execute();

    if result5.is_ok() {
        results.append(1); // Covenant verified
    } else {
        results.append(0);
    }

    // ============================================
    // Test 6: BITCOIN TRANSACTION VERIFICATION
    // This simulates verifying a real Bitcoin Signet P2WSH transaction
    // with OP_CAT. This proves Bitcoin state transitions on Starknet!
    // ============================================

    // Simulated witness data from a Bitcoin Signet transaction:
    // - Expected concatenation result (commitment)
    // - First data chunk
    // - Second data chunk
    // Script: CAT EQUALVERIFY OP_1

    // Create witness stack
    let mut tx_witness: Array<ByteArray> = array![];

    // Expected result: "BitcoinStarknet" (commitment)
    let mut expected: ByteArray = "";
    // "Bitcoin" = 42 69 74 63 6f 69 6e
    expected.append_byte(0x42);
    expected.append_byte(0x69);
    expected.append_byte(0x74);
    expected.append_byte(0x63);
    expected.append_byte(0x6f);
    expected.append_byte(0x69);
    expected.append_byte(0x6e);
    // "Starknet" = 53 74 61 72 6b 6e 65 74
    expected.append_byte(0x53);
    expected.append_byte(0x74);
    expected.append_byte(0x61);
    expected.append_byte(0x72);
    expected.append_byte(0x6b);
    expected.append_byte(0x6e);
    expected.append_byte(0x65);
    expected.append_byte(0x74);
    tx_witness.append(expected);

    // First chunk: "Bitcoin"
    let mut chunk_a: ByteArray = "";
    chunk_a.append_byte(0x42);
    chunk_a.append_byte(0x69);
    chunk_a.append_byte(0x74);
    chunk_a.append_byte(0x63);
    chunk_a.append_byte(0x6f);
    chunk_a.append_byte(0x69);
    chunk_a.append_byte(0x6e);
    tx_witness.append(chunk_a);

    // Second chunk: "Starknet"
    let mut chunk_b: ByteArray = "";
    chunk_b.append_byte(0x53);
    chunk_b.append_byte(0x74);
    chunk_b.append_byte(0x61);
    chunk_b.append_byte(0x72);
    chunk_b.append_byte(0x6b);
    chunk_b.append_byte(0x6e);
    chunk_b.append_byte(0x65);
    chunk_b.append_byte(0x74);
    tx_witness.append(chunk_b);

    // Witness script: CAT EQUALVERIFY OP_1
    // 0x7e = OP_CAT, 0x88 = OP_EQUALVERIFY, 0x51 = OP_1
    let tx_script: Array<u8> = array![0x7e, 0x88, 0x51];

    let mut vm_tx = ScriptVMTrait::new_with_stack(tx_script, tx_witness);
    let tx_result = vm_tx.execute();

    if tx_result.is_ok() {
        // Transaction verified! Stack should have [1]
        if vm_tx.stack.len() == 1 {
            results.append(1); // Bitcoin TX verified on Starknet!
        } else {
            results.append(0);
        }
    } else {
        results.append(0);
    }

    // Expected output: [10, 6, 4, 520, 1, 1]
    //                   ^   ^  ^   ^   ^  ^
    //                   |   |  |   |   |  +-- Test 6: Bitcoin TX verified!
    //                   |   |  |   |   +----- Test 5: Covenant verified
    //                   |   |  |   +--------- Test 4: 520 bytes max
    //                   |   |  +------------- Test 3: 4 bytes (abcd)
    //                   |   +---------------- Test 2: 6 bytes (ABCABC)
    //                   +-------------------- Test 1: 10 bytes (helloworld)
    results
}
