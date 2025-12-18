pub mod opcodes;
pub mod vm;
pub mod covenant;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_vectors;

#[cfg(test)]
mod test_fuzzing;

#[cfg(test)]
mod test_bitcoin_ground_truth;

// ============================================
// Provable Execution Demo
// ============================================

use vm::ScriptVMTrait;
use opcodes::{OP_PUSH, OP_CAT, OP_DUP, OP_VERIFY};

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
        OP_PUSH, 5, 0x68, 0x65, 0x6c, 0x6c, 0x6f,  // PUSH "hello"
        OP_PUSH, 5, 0x77, 0x6f, 0x72, 0x6c, 0x64,  // PUSH "world"
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
        OP_PUSH, 3, 0x41, 0x42, 0x43,  // PUSH "ABC"
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
        OP_PUSH, 1, 0x61,  // "a"
        OP_PUSH, 1, 0x62,  // "b"
        OP_PUSH, 1, 0x63,  // "c"
        OP_PUSH, 1, 0x64,  // "d"
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
        OP_PUSH, 4, 0xde, 0xad, 0xbe, 0xef,
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

    // Expected output: [10, 6, 4, 520, 1]
    results
}
