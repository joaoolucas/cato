/// Bitcoin Script Test Vector Tests
///
/// These tests are derived from the JSON test vectors in test_vectors/
/// and verify that Cato produces identical results to Bitcoin Script.
///
/// Test vector format:
/// - initial_stack: Hex-encoded bytes on stack before execution
/// - script: Hex-encoded opcodes to execute
/// - expected_final_stack: Expected hex-encoded bytes after execution
/// - expected_error: Expected error type (if script should fail)

use crate::vm::{ScriptVMTrait, VMError};
use crate::opcodes::{OP_ADD, OP_CAT, OP_DUP, OP_VERIFY};

/// Helper to create ByteArray from bytes
fn bytes_to_bytearray(bytes: Span<u8>) -> ByteArray {
    let mut result: ByteArray = "";
    let mut i: usize = 0;
    while i < bytes.len() {
        result.append_byte(*bytes.at(i));
        i += 1;
    };
    result
}

/// Helper to compare ByteArray with expected bytes
fn assert_bytearray_eq(actual: @ByteArray, expected: Span<u8>, msg: ByteArray) {
    assert!(actual.len() == expected.len(), "{} - length mismatch: {} vs {}", msg, actual.len(), expected.len());
    let mut i: usize = 0;
    while i < expected.len() {
        assert!(actual.at(i).unwrap() == *expected.at(i), "{} - byte {} mismatch", msg, i);
        i += 1;
    };
}

// ============================================
// OP_CAT Test Vectors (from test_vectors/op_cat.json)
// ============================================

#[test]
fn test_vector_cat_basic_hello_world() {
    // Concatenate 'hello' (68656c6c6f) and 'world' (776f726c64)
    // Expected: 'helloworld' (68656c6c6f776f726c64)
    let initial_a: Array<u8> = array![0x68, 0x65, 0x6c, 0x6c, 0x6f]; // "hello"
    let initial_b: Array<u8> = array![0x77, 0x6f, 0x72, 0x6c, 0x64]; // "world"

    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(initial_a.span()));
    stack.append(bytes_to_bytearray(initial_b.span()));

    let script: Array<u8> = array![OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    let result = vm.execute();
    assert!(result.is_ok(), "cat_basic_hello_world should succeed");
    assert!(vm.stack.len() == 1, "should have one element");

    let expected: Array<u8> = array![0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x6f, 0x72, 0x6c, 0x64];
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "cat_basic_hello_world");
}

#[test]
fn test_vector_cat_empty_left() {
    // Empty + 'abc' (616263) = 'abc'
    let mut stack: Array<ByteArray> = array![];
    stack.append(""); // empty
    stack.append(bytes_to_bytearray(array![0x61, 0x62, 0x63].span())); // "abc"

    let script: Array<u8> = array![OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "cat_empty_left should succeed");
    let expected: Array<u8> = array![0x61, 0x62, 0x63];
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "cat_empty_left");
}

#[test]
fn test_vector_cat_empty_right() {
    // 'abc' + empty = 'abc'
    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(array![0x61, 0x62, 0x63].span()));
    stack.append("");

    let script: Array<u8> = array![OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "cat_empty_right should succeed");
    let expected: Array<u8> = array![0x61, 0x62, 0x63];
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "cat_empty_right");
}

#[test]
fn test_vector_cat_both_empty() {
    let mut stack: Array<ByteArray> = array![];
    stack.append("");
    stack.append("");

    let script: Array<u8> = array![OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "cat_both_empty should succeed");
    assert!(vm.stack.at(0).len() == 0, "result should be empty");
}

#[test]
fn test_vector_cat_single_bytes() {
    // 0x01 + 0x02 = 0x0102
    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(array![0x01].span()));
    stack.append(bytes_to_bytearray(array![0x02].span()));

    let script: Array<u8> = array![OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "cat_single_bytes should succeed");
    let expected: Array<u8> = array![0x01, 0x02];
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "cat_single_bytes");
}

#[test]
fn test_vector_cat_binary_data() {
    // 0x00ff00 + 0xff00ff = 0x00ff00ff00ff
    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(array![0x00, 0xff, 0x00].span()));
    stack.append(bytes_to_bytearray(array![0xff, 0x00, 0xff].span()));

    let script: Array<u8> = array![OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "cat_binary_data should succeed");
    let expected: Array<u8> = array![0x00, 0xff, 0x00, 0xff, 0x00, 0xff];
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "cat_binary_data");
}

#[test]
fn test_vector_cat_triple_concat() {
    // Stack: ['a', 'b', 'c', 'd'] with script: CAT CAT CAT
    // Step 1: CAT on [c,d] -> [a,b,cd]
    // Step 2: CAT on [b,cd] -> [a,bcd]
    // Step 3: CAT on [a,bcd] -> [abcd]
    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(array![0x61].span())); // 'a'
    stack.append(bytes_to_bytearray(array![0x62].span())); // 'b'
    stack.append(bytes_to_bytearray(array![0x63].span())); // 'c'
    stack.append(bytes_to_bytearray(array![0x64].span())); // 'd'

    let script: Array<u8> = array![OP_CAT, OP_CAT, OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "cat_triple_concat should succeed");
    let expected: Array<u8> = array![0x61, 0x62, 0x63, 0x64]; // "abcd"
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "cat_triple_concat");
}

#[test]
fn test_vector_cat_with_dup() {
    // 'ABC' (414243), DUP, CAT = 'ABCABC'
    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(array![0x41, 0x42, 0x43].span()));

    let script: Array<u8> = array![OP_DUP, OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "cat_with_dup should succeed");
    let expected: Array<u8> = array![0x41, 0x42, 0x43, 0x41, 0x42, 0x43];
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "cat_with_dup");
}

#[test]
fn test_vector_cat_underflow_empty_stack() {
    let stack: Array<ByteArray> = array![];
    let script: Array<u8> = array![OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    let result = vm.execute();
    assert!(result.is_err(), "cat_underflow_empty should fail");
    assert!(result.unwrap_err() == VMError::StackUnderflow, "should be StackUnderflow");
}

#[test]
fn test_vector_cat_underflow_one_element() {
    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(array![0xde, 0xad, 0xbe, 0xef].span()));

    let script: Array<u8> = array![OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    let result = vm.execute();
    assert!(result.is_err(), "cat_underflow_one should fail");
    assert!(result.unwrap_err() == VMError::StackUnderflow, "should be StackUnderflow");
}

#[test]
fn test_vector_cat_preserves_other_stack() {
    // Stack: [0xaabbcc, 0x1122, 0x3344], CAT -> [0xaabbcc, 0x11223344]
    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(array![0xaa, 0xbb, 0xcc].span()));
    stack.append(bytes_to_bytearray(array![0x11, 0x22].span()));
    stack.append(bytes_to_bytearray(array![0x33, 0x44].span()));

    let script: Array<u8> = array![OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "cat_preserves should succeed");
    assert!(vm.stack.len() == 2, "should have two elements");

    let expected_bottom: Array<u8> = array![0xaa, 0xbb, 0xcc];
    let expected_top: Array<u8> = array![0x11, 0x22, 0x33, 0x44];
    assert_bytearray_eq(vm.stack.at(0), expected_bottom.span(), "cat_preserves bottom");
    assert_bytearray_eq(vm.stack.at(1), expected_top.span(), "cat_preserves top");
}

// ============================================
// OP_ADD Test Vectors (from test_vectors/op_add.json)
// ============================================

#[test]
fn test_vector_add_small_positives() {
    // 2 + 3 = 5
    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(array![0x02].span()));
    stack.append(bytes_to_bytearray(array![0x03].span()));

    let script: Array<u8> = array![OP_ADD];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "add_small_positives should succeed");
    let expected: Array<u8> = array![0x05];
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "add_small_positives");
}

#[test]
fn test_vector_add_zero_left() {
    // 0 + 42 = 42 (zero is empty bytearray)
    let mut stack: Array<ByteArray> = array![];
    stack.append("");
    stack.append(bytes_to_bytearray(array![0x2a].span()));

    let script: Array<u8> = array![OP_ADD];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "add_zero_left should succeed");
    let expected: Array<u8> = array![0x2a];
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "add_zero_left");
}

#[test]
fn test_vector_add_negative_positive() {
    // -5 + 10 = 5
    // -5 in Bitcoin: 0x85 (5 with sign bit)
    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(array![0x85].span())); // -5
    stack.append(bytes_to_bytearray(array![0x0a].span())); // 10

    let script: Array<u8> = array![OP_ADD];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "add_negative_positive should succeed");
    let expected: Array<u8> = array![0x05];
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "add_negative_positive");
}

#[test]
fn test_vector_add_127_plus_1() {
    // 127 + 1 = 128
    // 128 requires 2 bytes in Bitcoin: 0x80 0x00 (value 128 with sign byte)
    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(array![0x7f].span())); // 127
    stack.append(bytes_to_bytearray(array![0x01].span())); // 1

    let script: Array<u8> = array![OP_ADD];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "add_127_plus_1 should succeed");
    // 128 = 0x80, but high bit set means negative, so we need 0x8000 in little-endian
    let expected: Array<u8> = array![0x80, 0x00];
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "add_127_plus_1");
}

// ============================================
// Combined Script Test Vectors
// ============================================

#[test]
fn test_vector_push_cat_basic() {
    // Script: PUSH 'AB' PUSH 'CD' CAT
    // 02 41 42 02 43 44 7e
    let script: Array<u8> = array![
        0x02, 0x41, 0x42,  // PUSH_2 "AB"
        0x02, 0x43, 0x44,  // PUSH_2 "CD"
        OP_CAT
    ];

    let mut vm = ScriptVMTrait::new(script);
    assert!(vm.execute().is_ok(), "push_cat_basic should succeed");

    let expected: Array<u8> = array![0x41, 0x42, 0x43, 0x44]; // "ABCD"
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "push_cat_basic");
}

#[test]
fn test_vector_dup_cat_double() {
    // Script: PUSH 'XY' DUP CAT = 'XYXY'
    let script: Array<u8> = array![
        0x02, 0x58, 0x59,  // PUSH_2 "XY"
        OP_DUP,
        OP_CAT
    ];

    let mut vm = ScriptVMTrait::new(script);
    assert!(vm.execute().is_ok(), "dup_cat_double should succeed");

    let expected: Array<u8> = array![0x58, 0x59, 0x58, 0x59]; // "XYXY"
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "dup_cat_double");
}

#[test]
fn test_vector_cat_with_pushed_data() {
    // Initial: 'cafe', Script: PUSH 'babe' CAT = 'cafebabe'
    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(array![0xca, 0xfe].span()));

    let script: Array<u8> = array![
        0x02, 0xba, 0xbe,  // PUSH_2 0xbabe
        OP_CAT
    ];

    let mut vm = ScriptVMTrait::new_with_stack(script, stack);
    assert!(vm.execute().is_ok(), "cat_with_pushed should succeed");

    let expected: Array<u8> = array![0xca, 0xfe, 0xba, 0xbe];
    assert_bytearray_eq(vm.stack.at(0), expected.span(), "cat_with_pushed");
}

#[test]
fn test_vector_verify_truthy_cat_result() {
    // Stack: [0x01, 0x02], CAT, VERIFY
    // CAT produces 0x0102 (truthy), VERIFY consumes it
    let mut stack: Array<ByteArray> = array![];
    stack.append(bytes_to_bytearray(array![0x01].span()));
    stack.append(bytes_to_bytearray(array![0x02].span()));

    let script: Array<u8> = array![OP_CAT, OP_VERIFY];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "verify_truthy_cat should succeed");
    assert!(vm.stack.len() == 0, "stack should be empty after verify");
}

#[test]
fn test_vector_cat_empty_verify_fails() {
    // Stack: ["", ""], CAT, VERIFY
    // CAT produces "" (falsy), VERIFY should fail
    let mut stack: Array<ByteArray> = array![];
    stack.append("");
    stack.append("");

    let script: Array<u8> = array![OP_CAT, OP_VERIFY];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    let result = vm.execute();
    assert!(result.is_err(), "cat_empty_verify should fail");
    assert!(result.unwrap_err() == VMError::ScriptFailed, "should be ScriptFailed");
}

// ============================================
// Large Element Test (260 + 260 = 520 bytes)
// ============================================

#[test]
fn test_vector_cat_max_element_size() {
    // Create two 260-byte elements that concatenate to exactly 520 bytes
    let mut elem_a: ByteArray = "";
    let mut elem_b: ByteArray = "";

    let mut i: u32 = 0;
    while i < 260 {
        elem_a.append_byte((i % 256).try_into().unwrap());
        elem_b.append_byte(((i + 128) % 256).try_into().unwrap());
        i += 1;
    };

    let mut stack: Array<ByteArray> = array![];
    stack.append(elem_a);
    stack.append(elem_b);

    let script: Array<u8> = array![OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    assert!(vm.execute().is_ok(), "cat_max_size should succeed");
    assert!(vm.stack.at(0).len() == 520, "result should be 520 bytes");
}

#[test]
fn test_vector_cat_exceeds_max_size() {
    // Create two 261-byte elements - concatenation would exceed 520 limit
    let mut elem_a: ByteArray = "";
    let mut elem_b: ByteArray = "";

    let mut i: u32 = 0;
    while i < 261 {
        elem_a.append_byte((i % 256).try_into().unwrap());
        elem_b.append_byte((i % 256).try_into().unwrap());
        i += 1;
    };

    let mut stack: Array<ByteArray> = array![];
    stack.append(elem_a);
    stack.append(elem_b);

    let script: Array<u8> = array![OP_CAT];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);

    let result = vm.execute();
    assert!(result.is_err(), "cat_exceeds_max should fail");
    assert!(result.unwrap_err() == VMError::ElementTooLarge, "should be ElementTooLarge");
}
