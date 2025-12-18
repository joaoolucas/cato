/// Comprehensive Tests for Cato Bitcoin Script VM OP_CAT
///
/// These tests verify OP_CAT correctness with various inputs,
/// ensuring the Cairo VM doesn't crash and produces correct concatenation results.
/// Tests cover edge cases, boundary conditions, and random-like patterns.

use crate::vm::{ScriptVMTrait, VMError, MAX_ELEMENT_SIZE};
use crate::opcodes::OP_CAT;

/// Helper to create a ByteArray of specified length filled with a pattern
fn create_pattern_bytes(length: u32, seed: u8) -> ByteArray {
    let mut result: ByteArray = "";
    let mut i: u32 = 0;
    while i < length {
        let byte: u8 = ((seed.into() + i) % 256).try_into().unwrap();
        result.append_byte(byte);
        i += 1;
    };
    result
}

/// Helper to verify concatenation is correct
fn verify_concat(a: @ByteArray, b: @ByteArray, result: @ByteArray) -> bool {
    if result.len() != a.len() + b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len() {
        if result.at(i).unwrap() != a.at(i).unwrap() {
            return false;
        }
        i += 1;
    };
    let mut j: usize = 0;
    while j < b.len() {
        if result.at(a.len() + j).unwrap() != b.at(j).unwrap() {
            return false;
        }
        j += 1;
    };
    true
}

// ============================================
// Comprehensive OP_CAT Tests
// ============================================

/// Test various small length combinations
#[test]
fn test_cat_small_lengths_comprehensive() {
    // Test 16 different combinations of small lengths
    let mut test_case: u32 = 0;
    while test_case < 16 {
        let len_a: u32 = (test_case % 4) * 16;
        let len_b: u32 = ((test_case / 4) % 4) * 16;
        let seed_a: u8 = ((test_case * 17) % 256).try_into().unwrap();
        let seed_b: u8 = ((test_case * 31) % 256).try_into().unwrap();

        let elem_a = create_pattern_bytes(len_a, seed_a);
        let elem_b = create_pattern_bytes(len_b, seed_b);
        let elem_a_copy = create_pattern_bytes(len_a, seed_a);
        let elem_b_copy = create_pattern_bytes(len_b, seed_b);

        let mut stack: Array<ByteArray> = array![];
        stack.append(elem_a);
        stack.append(elem_b);

        let script: Array<u8> = array![OP_CAT];
        let mut vm = ScriptVMTrait::new_with_stack(script, stack);

        let result = vm.execute();
        assert!(result.is_ok(), "small length test should succeed");
        assert!(vm.stack.len() == 1, "should have one result");
        assert!(
            verify_concat(@elem_a_copy, @elem_b_copy, vm.stack.at(0)),
            "concatenation should be correct"
        );

        test_case += 1;
    };
}

/// Test medium-sized inputs with various lengths
#[test]
fn test_cat_medium_lengths_comprehensive() {
    // Test 20 different medium length combinations
    let mut test_case: u32 = 0;
    while test_case < 20 {
        let len_a: u32 = test_case * 25;
        let len_b: u32 = 500 - (test_case * 25); // Keep total at 500 (under 520)
        let seed_a: u8 = ((test_case * 13) % 256).try_into().unwrap();
        let seed_b: u8 = ((test_case * 29) % 256).try_into().unwrap();

        let elem_a = create_pattern_bytes(len_a, seed_a);
        let elem_b = create_pattern_bytes(len_b, seed_b);
        let elem_a_copy = create_pattern_bytes(len_a, seed_a);
        let elem_b_copy = create_pattern_bytes(len_b, seed_b);

        let mut stack: Array<ByteArray> = array![];
        stack.append(elem_a);
        stack.append(elem_b);

        let script: Array<u8> = array![OP_CAT];
        let mut vm = ScriptVMTrait::new_with_stack(script, stack);

        let result = vm.execute();
        assert!(result.is_ok(), "medium length test should succeed");
        assert!(
            verify_concat(@elem_a_copy, @elem_b_copy, vm.stack.at(0)),
            "concatenation should be correct"
        );

        test_case += 1;
    };
}

/// Test boundary around 520 bytes
#[test]
fn test_cat_boundary_520() {
    // Test totals from 510 to 530 bytes (520 is max valid)
    let mut total: u32 = 510;
    while total <= 530 {
        let len_a: u32 = total / 2;
        let len_b: u32 = total - len_a;

        if len_a > MAX_ELEMENT_SIZE || len_b > MAX_ELEMENT_SIZE {
            total += 1;
            continue;
        }

        let seed_a: u8 = (total % 256).try_into().unwrap();
        let seed_b: u8 = ((total + 128) % 256).try_into().unwrap();

        let elem_a = create_pattern_bytes(len_a, seed_a);
        let elem_b = create_pattern_bytes(len_b, seed_b);

        let mut stack: Array<ByteArray> = array![];
        stack.append(elem_a);
        stack.append(elem_b);

        let script: Array<u8> = array![OP_CAT];
        let mut vm = ScriptVMTrait::new_with_stack(script, stack);

        let result = vm.execute();

        if total <= 520 {
            assert!(result.is_ok(), "should succeed at or below 520 bytes");
            assert!(vm.stack.at(0).len() == total.try_into().unwrap(), "length should match");
        } else {
            assert!(result.is_err(), "should fail above 520 bytes");
            assert!(result.unwrap_err() == VMError::ElementTooLarge, "should be ElementTooLarge");
        }

        total += 1;
    };
}

/// Test exactly 520 bytes (max valid) with various seeds
#[test]
fn test_cat_max_520_bytes() {
    let mut seed: u8 = 0;
    while seed < 10 {
        let elem_a = create_pattern_bytes(260, seed);
        let elem_b = create_pattern_bytes(260, seed + 128);
        let elem_a_copy = create_pattern_bytes(260, seed);
        let elem_b_copy = create_pattern_bytes(260, seed + 128);

        let mut stack: Array<ByteArray> = array![];
        stack.append(elem_a);
        stack.append(elem_b);

        let script: Array<u8> = array![OP_CAT];
        let mut vm = ScriptVMTrait::new_with_stack(script, stack);

        let result = vm.execute();
        assert!(result.is_ok(), "520 bytes should always succeed");
        assert!(vm.stack.at(0).len() == 520, "result should be 520 bytes");
        assert!(
            verify_concat(@elem_a_copy, @elem_b_copy, vm.stack.at(0)),
            "concatenation should be correct"
        );

        seed += 1;
    };
}

/// Test all 256 byte values are preserved correctly through CAT
#[test]
fn test_cat_all_byte_values_preserved() {
    // Create two 128-byte elements containing all possible byte values (0x00-0xFF)
    let mut elem_a: ByteArray = "";
    let mut elem_b: ByteArray = "";

    let mut i: u16 = 0;
    while i < 128 {
        elem_a.append_byte(i.try_into().unwrap());
        elem_b.append_byte((i + 128).try_into().unwrap());
        i += 1;
    };

    let mut stack: Array<ByteArray> = array![];
    stack.append(elem_a);
    stack.append(elem_b);

    let script: Array<u8> = array![OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    let result = vm.execute();
    assert!(result.is_ok(), "byte preservation test should succeed");

    let concat = vm.stack.at(0);
    assert!(concat.len() == 256, "result should be 256 bytes");

    // Verify each byte value is preserved
    let mut j: u16 = 0;
    while j < 256 {
        let expected: u8 = j.try_into().unwrap();
        let actual = concat.at(j.try_into().unwrap()).unwrap();
        assert!(actual == expected, "byte value should be preserved");
        j += 1;
    };
}

/// Test CAT with empty elements in various positions
#[test]
fn test_cat_with_empty_elements() {
    // Test empty + non-empty
    let mut len: u32 = 0;
    while len <= 100 {
        let non_empty = create_pattern_bytes(len, (len % 256).try_into().unwrap());
        let non_empty_copy = create_pattern_bytes(len, (len % 256).try_into().unwrap());

        // Test: empty + non_empty
        let mut stack1: Array<ByteArray> = array![];
        stack1.append("");
        stack1.append(non_empty);
        let mut vm1 = ScriptVMTrait::new_with_stack(array![OP_CAT], stack1);
        assert!(vm1.execute().is_ok(), "empty + data should succeed");
        assert!(vm1.stack.at(0).len() == non_empty_copy.len(), "length should match");

        // Test: non_empty + empty
        let non_empty2 = create_pattern_bytes(len, (len % 256).try_into().unwrap());
        let mut stack2: Array<ByteArray> = array![];
        stack2.append(non_empty2);
        stack2.append("");
        let mut vm2 = ScriptVMTrait::new_with_stack(array![OP_CAT], stack2);
        assert!(vm2.execute().is_ok(), "data + empty should succeed");
        assert!(vm2.stack.at(0).len() == non_empty_copy.len(), "length should match");

        len += 25;
    };
}

/// Test chained CAT operations
#[test]
fn test_cat_chain_operations() {
    // Test chaining 4 elements with 3 CATs
    let mut seed: u8 = 0;
    while seed < 10 {
        let elem1 = create_pattern_bytes(32, seed);
        let elem2 = create_pattern_bytes(32, seed + 64);
        let elem3 = create_pattern_bytes(32, seed + 128);
        let elem4 = create_pattern_bytes(32, seed + 192);

        let mut stack: Array<ByteArray> = array![];
        stack.append(elem1);
        stack.append(elem2);
        stack.append(elem3);
        stack.append(elem4);

        // CAT three times
        let script: Array<u8> = array![OP_CAT, OP_CAT, OP_CAT];
        let mut vm = ScriptVMTrait::new_with_stack(script, stack);

        let result = vm.execute();
        assert!(result.is_ok(), "chained cat should succeed");
        assert!(vm.stack.len() == 1, "should have one result");
        assert!(vm.stack.at(0).len() == 128, "length should be 4x32=128");

        seed += 1;
    };
}

/// Property: CAT result length equals sum of input lengths
#[test]
fn test_property_length_additive() {
    let mut test_case: u32 = 0;
    while test_case < 25 {
        let len_a: u32 = test_case * 20;
        let len_b: u32 = 500 - len_a;
        let seed: u8 = (test_case % 256).try_into().unwrap();
        let seed_b: u8 = ((seed.into() + 1_u16) % 256).try_into().unwrap();

        let elem_a = create_pattern_bytes(len_a, seed);
        let elem_b = create_pattern_bytes(len_b, seed_b);

        let expected_len = len_a + len_b;

        let mut stack: Array<ByteArray> = array![];
        stack.append(elem_a);
        stack.append(elem_b);

        let script: Array<u8> = array![OP_CAT];
        let mut vm = ScriptVMTrait::new_with_stack(script, stack);

        let result = vm.execute();
        assert!(result.is_ok(), "should succeed within limits");
        assert!(
            vm.stack.at(0).len() == expected_len.try_into().unwrap(),
            "result length should equal sum of input lengths"
        );

        test_case += 1;
    };
}

/// Property: CAT with identity (empty string)
#[test]
fn test_property_identity() {
    let mut len: u32 = 0;
    while len <= 256 {
        let seed: u8 = (len % 256).try_into().unwrap();
        let a1 = create_pattern_bytes(len, seed);
        let a2 = create_pattern_bytes(len, seed);
        let a3 = create_pattern_bytes(len, seed);

        // Test: a CAT "" = a
        let mut stack1: Array<ByteArray> = array![];
        stack1.append(a1);
        stack1.append("");
        let mut vm1 = ScriptVMTrait::new_with_stack(array![OP_CAT], stack1);
        assert!(vm1.execute().is_ok(), "a CAT empty should succeed");
        assert!(vm1.stack.at(0).len() == a2.len(), "a CAT empty = a (length)");

        // Verify content
        let mut i: usize = 0;
        while i < a2.len() {
            assert!(vm1.stack.at(0).at(i).unwrap() == a2.at(i).unwrap(), "content should match");
            i += 1;
        };

        // Test: "" CAT a = a
        let mut stack2: Array<ByteArray> = array![];
        stack2.append("");
        stack2.append(a3);
        let mut vm2 = ScriptVMTrait::new_with_stack(array![OP_CAT], stack2);
        assert!(vm2.execute().is_ok(), "empty CAT a should succeed");
        assert!(vm2.stack.at(0).len() == len.try_into().unwrap(), "empty CAT a = a (length)");

        len += 32;
    };
}

/// Property: Byte order is preserved in concatenation
#[test]
fn test_property_byte_order_preserved() {
    let mut offset: u8 = 0;
    while offset < 64 {
        let mut elem_a: ByteArray = "";
        let mut elem_b: ByteArray = "";

        // Create elements with sequential bytes
        let mut i: u8 = 0;
        while i < 64 {
            elem_a.append_byte(offset + i);
            elem_b.append_byte(offset + 64 + i);
            i += 1;
        };

        let mut stack: Array<ByteArray> = array![];
        stack.append(elem_a);
        stack.append(elem_b);

        let script: Array<u8> = array![OP_CAT];
        let mut vm = ScriptVMTrait::new_with_stack(script, stack);

        assert!(vm.execute().is_ok(), "should succeed");

        let result = vm.stack.at(0);
        assert!(result.len() == 128, "should be 128 bytes");

        // Verify first 64 bytes
        let mut j: u8 = 0;
        while j < 64 {
            assert!(result.at(j.into()).unwrap() == offset + j, "first half order preserved");
            j += 1;
        };

        // Verify last 64 bytes
        let mut k: u8 = 0;
        while k < 64 {
            assert!(result.at((64 + k).into()).unwrap() == offset + 64 + k, "second half order preserved");
            k += 1;
        };

        offset += 8;
    };
}

/// Test exceeds max size fails correctly
#[test]
fn test_cat_exceeds_max_size_fails() {
    // Test sizes that exceed 520: 261+261=522, 300+300=600, etc.
    let test_sizes: Array<(u32, u32)> = array![
        (261, 261),
        (300, 300),
        (400, 200),
        (520, 1),
        (1, 520)
    ];

    let mut i: usize = 0;
    while i < test_sizes.len() {
        let (len_a, len_b) = *test_sizes.at(i);

        let elem_a = create_pattern_bytes(len_a, 0xaa);
        let elem_b = create_pattern_bytes(len_b, 0xbb);

        let mut stack: Array<ByteArray> = array![];
        stack.append(elem_a);
        stack.append(elem_b);

        let script: Array<u8> = array![OP_CAT];
        let mut vm = ScriptVMTrait::new_with_stack(script, stack);

        let result = vm.execute();
        assert!(result.is_err(), "should fail when exceeding 520 bytes");
        assert!(result.unwrap_err() == VMError::ElementTooLarge, "should be ElementTooLarge");

        i += 1;
    };
}
