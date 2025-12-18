/// Test Suite for Cato Bitcoin Script VM
///
/// Tests for the VM execution, opcodes, and covenant verification

use crate::vm::{ScriptVMTrait, VMError, decode_script_num, encode_script_num, is_truthy};
use crate::covenant::{CovenantTrait, CovenantBuilderTrait};
use crate::opcodes::{OP_ADD, OP_CAT, OP_DUP, OP_DROP, OP_EQUAL, OP_VERIFY, OP_0};

// ============================================
// OP_CAT Tests
// ============================================

#[test]
fn test_op_cat_concatenation() {
    // Script: PUSH "hello" PUSH "world" OP_CAT
    // Expected result: "helloworld" on stack

    let bytecode: Array<u8> = array![
        0x05, 'h', 'e', 'l', 'l', 'o',     // PUSH_5 "hello"
        0x05, 'w', 'o', 'r', 'l', 'd',     // PUSH_5 "world"
        OP_CAT                              // OP_CAT
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    assert!(vm.stack.len() == 1, "should have one element on stack");

    // Verify the concatenation result is "helloworld"
    let top = vm.stack.at(0);
    assert!(top.len() == 10, "result should be 10 bytes");
    assert!(top.at(0).unwrap() == 'h', "byte 0 should be 'h'");
    assert!(top.at(1).unwrap() == 'e', "byte 1 should be 'e'");
    assert!(top.at(2).unwrap() == 'l', "byte 2 should be 'l'");
    assert!(top.at(3).unwrap() == 'l', "byte 3 should be 'l'");
    assert!(top.at(4).unwrap() == 'o', "byte 4 should be 'o'");
    assert!(top.at(5).unwrap() == 'w', "byte 5 should be 'w'");
    assert!(top.at(6).unwrap() == 'o', "byte 6 should be 'o'");
    assert!(top.at(7).unwrap() == 'r', "byte 7 should be 'r'");
    assert!(top.at(8).unwrap() == 'l', "byte 8 should be 'l'");
    assert!(top.at(9).unwrap() == 'd', "byte 9 should be 'd'");
}

#[test]
fn test_op_cat_empty_strings() {
    // Script: PUSH "" PUSH "" OP_CAT
    // Expected: empty string on stack

    let bytecode: Array<u8> = array![
        OP_0,     // PUSH ""
        OP_0,     // PUSH ""
        OP_CAT    // OP_CAT
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    assert!(vm.stack.len() == 1, "should have one element");
    assert!(vm.stack.at(0).len() == 0, "result should be empty");
}

#[test]
fn test_op_cat_underflow() {
    // Script: PUSH "hello" OP_CAT (only one element)
    // Expected: StackUnderflow error

    let bytecode: Array<u8> = array![
        0x05, 'h', 'e', 'l', 'l', 'o',  // PUSH_5 "hello"
        OP_CAT
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_err(), "should fail with underflow");
    assert!(result.unwrap_err() == VMError::StackUnderflow, "error should be StackUnderflow");
}

// ============================================
// OP_ADD Tests
// ============================================

#[test]
fn test_op_add_positive_numbers() {
    // Script: PUSH 2 PUSH 3 OP_ADD
    // Expected: 5 on stack

    // Encode numbers as script nums (little-endian)
    let bytecode: Array<u8> = array![
        0x01, 2,      // PUSH_1 2
        0x01, 3,      // PUSH_1 3
        OP_ADD        // OP_ADD
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    assert!(vm.stack.len() == 1, "should have one element");

    let result_num = decode_script_num(vm.stack.at(0));
    assert!(result_num == 5, "2 + 3 should equal 5");
}

#[test]
fn test_op_add_with_zero() {
    // Script: PUSH 42 PUSH 0 OP_ADD
    // Expected: 42 on stack

    let bytecode: Array<u8> = array![
        0x01, 42,     // PUSH_1 42
        OP_0,         // PUSH 0 (empty = 0)
        OP_ADD        // OP_ADD
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");

    let result_num = decode_script_num(vm.stack.at(0));
    assert!(result_num == 42, "42 + 0 should equal 42");
}

#[test]
fn test_op_add_negative_numbers() {
    // Script: PUSH -5 PUSH 10 OP_ADD
    // Expected: 5 on stack
    // -5 in script num format: 0x85 (5 with sign bit set in same byte)

    let bytecode: Array<u8> = array![
        0x01, 0x85,   // PUSH_1 -5
        0x01, 10,     // PUSH_1 10
        OP_ADD        // OP_ADD
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");

    let result_num = decode_script_num(vm.stack.at(0));
    assert!(result_num == 5, "-5 + 10 should equal 5");
}

// ============================================
// Direct Push Tests (0x01-0x4b)
// ============================================

#[test]
fn test_op_push_basic() {
    let bytecode: Array<u8> = array![
        0x03, 'a', 'b', 'c'  // PUSH_3 "abc"
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    assert!(vm.stack.len() == 1, "should have one element");
    assert!(vm.stack.at(0).len() == 3, "element should be 3 bytes");
}

#[test]
fn test_op_push_multiple() {
    let bytecode: Array<u8> = array![
        0x01, 'x',      // PUSH_1 "x"
        0x02, 'y', 'z'  // PUSH_2 "yz"
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    assert!(vm.stack.len() == 2, "should have two elements");
}

// ============================================
// OP_DUP Tests
// ============================================

#[test]
fn test_op_dup() {
    let bytecode: Array<u8> = array![
        0x03, 'f', 'o', 'o',  // PUSH_3 "foo"
        OP_DUP
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    assert!(vm.stack.len() == 2, "should have two elements");

    // Both elements should be "foo"
    let first = vm.stack.at(0);
    let second = vm.stack.at(1);
    assert!(first.len() == 3 && second.len() == 3, "both should be 3 bytes");
}

// ============================================
// OP_DROP Tests
// ============================================

#[test]
fn test_op_drop() {
    let bytecode: Array<u8> = array![
        0x01, 'a',  // PUSH_1 "a"
        0x01, 'b',  // PUSH_1 "b"
        OP_DROP
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    assert!(vm.stack.len() == 1, "should have one element after drop");
}

// ============================================
// OP_EQUAL Tests
// ============================================

#[test]
fn test_op_equal_same() {
    let bytecode: Array<u8> = array![
        0x03, 'a', 'b', 'c',  // PUSH_3 "abc"
        0x03, 'a', 'b', 'c',  // PUSH_3 "abc"
        OP_EQUAL
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    assert!(vm.stack.len() == 1, "should have one element");

    let result_num = decode_script_num(vm.stack.at(0));
    assert!(result_num == 1, "equal elements should push 1");
}

#[test]
fn test_op_equal_different() {
    let bytecode: Array<u8> = array![
        0x03, 'a', 'b', 'c',  // PUSH_3 "abc"
        0x03, 'x', 'y', 'z',  // PUSH_3 "xyz"
        OP_EQUAL
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");

    let result_num = decode_script_num(vm.stack.at(0));
    assert!(result_num == 0, "different elements should push 0");
}

// ============================================
// OP_VERIFY Tests
// ============================================

#[test]
fn test_op_verify_truthy() {
    let bytecode: Array<u8> = array![
        0x01, 1,      // PUSH_1 truthy value
        OP_VERIFY,
        0x01, 42      // PUSH_1 final result
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    assert!(vm.stack.len() == 1, "should have one element after verify");
}

#[test]
fn test_op_verify_falsy() {
    let bytecode: Array<u8> = array![
        OP_0,         // Push empty (falsy)
        OP_VERIFY     // Should fail
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_err(), "should fail on verify");
    assert!(result.unwrap_err() == VMError::ScriptFailed, "error should be ScriptFailed");
}

// ============================================
// Number Encoding Tests
// ============================================

#[test]
fn test_encode_decode_zero() {
    let encoded = encode_script_num(0);
    assert!(encoded.len() == 0, "zero should encode to empty");

    let decoded = decode_script_num(@encoded);
    assert!(decoded == 0, "should decode back to 0");
}

#[test]
fn test_encode_decode_positive() {
    let encoded = encode_script_num(127);
    let decoded = decode_script_num(@encoded);
    assert!(decoded == 127, "should round-trip 127");

    let encoded2 = encode_script_num(128);
    let decoded2 = decode_script_num(@encoded2);
    assert!(decoded2 == 128, "should round-trip 128");

    let encoded3 = encode_script_num(256);
    let decoded3 = decode_script_num(@encoded3);
    assert!(decoded3 == 256, "should round-trip 256");
}

#[test]
fn test_encode_decode_negative() {
    let encoded = encode_script_num(-1);
    let decoded = decode_script_num(@encoded);
    assert!(decoded == -1, "should round-trip -1");

    let encoded2 = encode_script_num(-127);
    let decoded2 = decode_script_num(@encoded2);
    assert!(decoded2 == -127, "should round-trip -127");
}

// ============================================
// Truthiness Tests
// ============================================

#[test]
fn test_is_truthy_empty() {
    let empty: ByteArray = "";
    assert!(!is_truthy(@empty), "empty should be falsy");
}

#[test]
fn test_is_truthy_zero() {
    let mut zero: ByteArray = "";
    zero.append_byte(0);
    assert!(!is_truthy(@zero), "single zero byte should be falsy");
}

#[test]
fn test_is_truthy_nonzero() {
    let mut nonzero: ByteArray = "";
    nonzero.append_byte(1);
    assert!(is_truthy(@nonzero), "nonzero should be truthy");
}

#[test]
fn test_is_truthy_negative_zero() {
    // 0x80 represents negative zero in Bitcoin script
    let mut neg_zero: ByteArray = "";
    neg_zero.append_byte(0x80);
    assert!(!is_truthy(@neg_zero), "negative zero (0x80) should be falsy");
}

// ============================================
// Covenant Tests
// ============================================

#[test]
fn test_covenant_verification_success() {
    // Create a covenant that pushes "hello" and "world", concatenates,
    // and leaves truthy result
    let mut builder = CovenantBuilderTrait::new();
    builder.push_data("hello");
    builder.push_data("world");
    builder.cat();
    let covenant = builder.build();

    // Empty input data since script has everything
    let input: Array<ByteArray> = array![];
    let result = covenant.verify(input);

    assert!(result, "covenant should verify successfully");
}

#[test]
fn test_covenant_with_input_data() {
    // Create a covenant that expects two strings on stack and concatenates
    let script: Array<u8> = array![OP_CAT];
    let covenant = CovenantTrait::new(script);

    // Provide input data
    let mut input: Array<ByteArray> = array![];
    let hello: ByteArray = "hello";
    let world: ByteArray = "world";
    input.append(hello);
    input.append(world);

    let result = covenant.verify(input);
    assert!(result, "covenant with input data should verify");
}

#[test]
fn test_covenant_verification_failure() {
    // Create a covenant that pushes empty (falsy) result
    let script: Array<u8> = array![OP_0];  // Push empty (falsy)
    let covenant = CovenantTrait::new(script);

    let input: Array<ByteArray> = array![];
    let result = covenant.verify(input);

    assert!(!result, "covenant with empty result should fail");
}

#[test]
fn test_covenant_multiple_stack_elements() {
    // Create a covenant that leaves two elements on stack (should fail)
    let script: Array<u8> = array![
        0x01, 'a',  // PUSH_1 "a"
        0x01, 'b'   // PUSH_1 "b"
    ];
    let covenant = CovenantTrait::new(script);

    let input: Array<ByteArray> = array![];
    let result = covenant.verify(input);

    assert!(!result, "covenant with multiple stack elements should fail");
}

// ============================================
// Complex Script Tests
// ============================================

#[test]
fn test_complex_cat_script() {
    // Script: PUSH "AB" PUSH "CD" OP_CAT
    // Expected: "ABCD" concatenated, which is truthy

    let mut builder = CovenantBuilderTrait::new();
    builder.push_data("AB");
    builder.push_data("CD");
    builder.cat();
    let covenant = builder.build();

    let input: Array<ByteArray> = array![];
    assert!(covenant.verify(input), "complex script should verify");
}

#[test]
fn test_dup_equal_verify_pattern() {
    // Script: PUSH "test" DUP EQUAL VERIFY PUSH 1
    // Tests: push, duplicate, compare equal (should be 1), verify, push final 1

    let bytecode: Array<u8> = array![
        0x04, 't', 'e', 's', 't',  // PUSH_4 "test"
        OP_DUP,
        OP_EQUAL,
        OP_VERIFY,
        0x01, 1  // PUSH_1 1
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "dup-equal-verify pattern should succeed");
    assert!(vm.stack.len() == 1, "should have final result on stack");
}

// ============================================
// Error Handling Tests
// ============================================

#[test]
fn test_invalid_opcode() {
    let bytecode: Array<u8> = array![0xFF];  // Invalid opcode

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_err(), "should fail on invalid opcode");
    assert!(result.unwrap_err() == VMError::InvalidOpcode, "error should be InvalidOpcode");
}

#[test]
fn test_push_invalid_length() {
    // Direct push opcode with length that exceeds remaining bytecode
    let bytecode: Array<u8> = array![0x20];  // PUSH_32 but no data follows

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_err(), "should fail on invalid push length");
    assert!(result.unwrap_err() == VMError::InvalidPushLength, "error should be InvalidPushLength");
}
