/// Test Suite for Cato Bitcoin Script VM

use crate::vm::{ScriptVMTrait, VMError, decode_script_num, encode_script_num, is_truthy};
use crate::opcodes::{OP_ADD, OP_CAT, OP_DUP, OP_DROP, OP_EQUAL, OP_VERIFY, OP_0};

// ============================================
// OP_CAT Tests
// ============================================

#[test]
fn test_op_cat_concatenation() {
    let bytecode: Array<u8> = array![
        0x05, 'h', 'e', 'l', 'l', 'o',
        0x05, 'w', 'o', 'r', 'l', 'd',
        OP_CAT
    ];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    assert!(vm.stack.len() == 1, "should have one element on stack");

    let top = vm.stack.at(0);
    assert!(top.len() == 10, "result should be 10 bytes");
}

#[test]
fn test_op_cat_empty_strings() {
    let bytecode: Array<u8> = array![OP_0, OP_0, OP_CAT];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    assert!(vm.stack.at(0).len() == 0, "result should be empty");
}

#[test]
fn test_op_cat_underflow() {
    let bytecode: Array<u8> = array![0x05, 'h', 'e', 'l', 'l', 'o', OP_CAT];

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
    let bytecode: Array<u8> = array![0x01, 2, 0x01, 3, OP_ADD];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    let result_num = decode_script_num(vm.stack.at(0));
    assert!(result_num == 5, "2 + 3 should equal 5");
}

#[test]
fn test_op_add_with_zero() {
    let bytecode: Array<u8> = array![0x01, 42, OP_0, OP_ADD];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    let result_num = decode_script_num(vm.stack.at(0));
    assert!(result_num == 42, "42 + 0 should equal 42");
}

#[test]
fn test_op_add_negative_numbers() {
    let bytecode: Array<u8> = array![0x01, 0x85, 0x01, 10, OP_ADD];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    let result_num = decode_script_num(vm.stack.at(0));
    assert!(result_num == 5, "-5 + 10 should equal 5");
}

// ============================================
// Stack Operation Tests
// ============================================

#[test]
fn test_op_dup() {
    let bytecode: Array<u8> = array![0x03, 'f', 'o', 'o', OP_DUP];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    assert!(vm.stack.len() == 2, "should have two elements");
}

#[test]
fn test_op_drop() {
    let bytecode: Array<u8> = array![0x01, 'a', 0x01, 'b', OP_DROP];

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
    let bytecode: Array<u8> = array![0x03, 'a', 'b', 'c', 0x03, 'a', 'b', 'c', OP_EQUAL];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
    let result_num = decode_script_num(vm.stack.at(0));
    assert!(result_num == 1, "equal elements should push 1");
}

#[test]
fn test_op_equal_different() {
    let bytecode: Array<u8> = array![0x03, 'a', 'b', 'c', 0x03, 'x', 'y', 'z', OP_EQUAL];

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
    let bytecode: Array<u8> = array![0x01, 1, OP_VERIFY, 0x01, 42];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_ok(), "execution should succeed");
}

#[test]
fn test_op_verify_falsy() {
    let bytecode: Array<u8> = array![OP_0, OP_VERIFY];

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
}

#[test]
fn test_encode_decode_negative() {
    let encoded = encode_script_num(-1);
    let decoded = decode_script_num(@encoded);
    assert!(decoded == -1, "should round-trip -1");
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

// ============================================
// Error Handling Tests
// ============================================

#[test]
fn test_invalid_opcode() {
    let bytecode: Array<u8> = array![0xFF];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_err(), "should fail on invalid opcode");
    assert!(result.unwrap_err() == VMError::InvalidOpcode, "error should be InvalidOpcode");
}

#[test]
fn test_push_invalid_length() {
    let bytecode: Array<u8> = array![0x20];

    let mut vm = ScriptVMTrait::new(bytecode);
    let result = vm.execute();

    assert!(result.is_err(), "should fail on invalid push length");
    assert!(result.unwrap_err() == VMError::InvalidPushLength, "error should be InvalidPushLength");
}
