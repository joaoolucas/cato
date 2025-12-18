/// Tests for new opcodes: OP_2-16, alt stack, ROLL, PICK, SHA256, CHECKSIGADD

use crate::vm::{ScriptVMTrait, VMError, sha256};
use crate::opcodes::{
    OP_CAT, OP_DUP, OP_DROP, OP_EQUAL, OP_EQUALVERIFY, OP_VERIFY,
    OP_1, OP_2, OP_3, OP_TOALTSTACK, OP_FROMALTSTACK, OP_ROLL, OP_PICK,
    OP_SHA256, OP_CHECKSIGADD, OP_SWAP
};

// ============================================
// OP_2 through OP_16 Tests
// ============================================

#[test]
fn test_op_2() {
    let script: Array<u8> = array![0x52]; // OP_2
    let mut vm = ScriptVMTrait::new(script);
    let result = vm.execute();
    assert!(result.is_ok(), "OP_2 should succeed");
    assert!(vm.stack.len() == 1, "Should have one element");
    assert!(vm.stack.at(0).at(0).unwrap() == 2, "Should be 2");
}

#[test]
fn test_op_16() {
    let script: Array<u8> = array![0x60]; // OP_16
    let mut vm = ScriptVMTrait::new(script);
    let result = vm.execute();
    assert!(result.is_ok(), "OP_16 should succeed");
    assert!(vm.stack.len() == 1, "Should have one element");
    assert!(vm.stack.at(0).at(0).unwrap() == 16, "Should be 16");
}

#[test]
fn test_push_all_numbers() {
    // Push 1 through 5 and verify stack
    let script: Array<u8> = array![0x51, 0x52, 0x53, 0x54, 0x55];
    let mut vm = ScriptVMTrait::new(script);
    let result = vm.execute();
    assert!(result.is_ok(), "Push numbers should succeed");
    assert!(vm.stack.len() == 5, "Should have 5 elements");
    assert!(vm.stack.at(0).at(0).unwrap() == 1, "First should be 1");
    assert!(vm.stack.at(4).at(0).unwrap() == 5, "Last should be 5");
}

// ============================================
// Alt Stack Tests
// ============================================

#[test]
fn test_toaltstack_fromaltstack() {
    // Push value, move to alt stack, move back
    let script: Array<u8> = array![
        0x03, 0xaa, 0xbb, 0xcc,  // PUSH_3 data
        OP_TOALTSTACK,           // Move to alt stack
        OP_FROMALTSTACK          // Move back
    ];
    let mut vm = ScriptVMTrait::new(script);
    let result = vm.execute();
    assert!(result.is_ok(), "Alt stack operations should succeed");
    assert!(vm.stack.len() == 1, "Should have one element on main stack");
    assert!(vm.alt_stack.len() == 0, "Alt stack should be empty");
    assert!(vm.stack.at(0).at(0).unwrap() == 0xaa, "Data should be preserved");
}

#[test]
fn test_toaltstack_preserves_order() {
    // Push two values, store one in alt stack, do operation, restore
    let script: Array<u8> = array![
        0x01, 0x01,       // PUSH_1 0x01
        0x01, 0x02,       // PUSH_1 0x02
        OP_TOALTSTACK,    // Move 2 to alt stack
        0x01, 0x03,       // PUSH_1 0x03
        OP_FROMALTSTACK   // Get 2 back
    ];
    let mut vm = ScriptVMTrait::new(script);
    let result = vm.execute();
    assert!(result.is_ok(), "Should succeed");
    assert!(vm.stack.len() == 3, "Should have 3 elements");
    // Stack should be: [1, 3, 2]
    assert!(vm.stack.at(0).at(0).unwrap() == 1, "Bottom should be 1");
    assert!(vm.stack.at(1).at(0).unwrap() == 3, "Middle should be 3");
    assert!(vm.stack.at(2).at(0).unwrap() == 2, "Top should be 2");
}

#[test]
fn test_fromaltstack_empty_fails() {
    let script: Array<u8> = array![OP_FROMALTSTACK];
    let mut vm = ScriptVMTrait::new(script);
    let result = vm.execute();
    assert!(result == Result::Err(VMError::StackUnderflow), "Empty alt stack should fail");
}

// ============================================
// OP_PICK Tests
// ============================================

#[test]
fn test_op_pick_zero() {
    // PICK 0 copies top element
    let mut stack: Array<ByteArray> = array![];
    let mut a: ByteArray = "";
    a.append_byte(0xaa);
    stack.append(a);
    let mut b: ByteArray = "";
    b.append_byte(0xbb);
    stack.append(b);
    let mut zero: ByteArray = "";
    zero.append_byte(0x00);
    stack.append(zero);  // n=0

    let script: Array<u8> = array![OP_PICK];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);
    let result = vm.execute();
    assert!(result.is_ok(), "PICK 0 should succeed");
    assert!(vm.stack.len() == 3, "Should have 3 elements");
    assert!(vm.stack.at(2).at(0).unwrap() == 0xbb, "Should copy bb (was top)");
}

#[test]
fn test_op_pick_one() {
    // PICK 1 copies second from top
    let mut stack: Array<ByteArray> = array![];
    let mut a: ByteArray = "";
    a.append_byte(0xaa);
    stack.append(a);
    let mut b: ByteArray = "";
    b.append_byte(0xbb);
    stack.append(b);
    let mut one: ByteArray = "";
    one.append_byte(0x01);
    stack.append(one);  // n=1

    let script: Array<u8> = array![OP_PICK];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);
    let result = vm.execute();
    assert!(result.is_ok(), "PICK 1 should succeed");
    assert!(vm.stack.len() == 3, "Should have 3 elements");
    assert!(vm.stack.at(2).at(0).unwrap() == 0xaa, "Should copy aa (second from top)");
}

// ============================================
// OP_ROLL Tests
// ============================================

#[test]
fn test_op_roll_zero() {
    // ROLL 0 does nothing (moves top to top)
    let mut stack: Array<ByteArray> = array![];
    let mut a: ByteArray = "";
    a.append_byte(0xaa);
    stack.append(a);
    let mut b: ByteArray = "";
    b.append_byte(0xbb);
    stack.append(b);
    let mut zero: ByteArray = "";
    zero.append_byte(0x00);
    stack.append(zero);  // n=0

    let script: Array<u8> = array![OP_ROLL];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);
    let result = vm.execute();
    assert!(result.is_ok(), "ROLL 0 should succeed");
    assert!(vm.stack.len() == 2, "Should have 2 elements");
    assert!(vm.stack.at(1).at(0).unwrap() == 0xbb, "Top should be bb");
}

#[test]
fn test_op_roll_one() {
    // ROLL 1 swaps top two (like SWAP)
    let mut stack: Array<ByteArray> = array![];
    let mut a: ByteArray = "";
    a.append_byte(0xaa);
    stack.append(a);
    let mut b: ByteArray = "";
    b.append_byte(0xbb);
    stack.append(b);
    let mut one: ByteArray = "";
    one.append_byte(0x01);
    stack.append(one);  // n=1

    let script: Array<u8> = array![OP_ROLL];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);
    let result = vm.execute();
    assert!(result.is_ok(), "ROLL 1 should succeed");
    assert!(vm.stack.len() == 2, "Should have 2 elements");
    // Stack: [aa, bb] -> ROLL 1 -> [bb, aa]
    assert!(vm.stack.at(0).at(0).unwrap() == 0xbb, "Bottom should be bb");
    assert!(vm.stack.at(1).at(0).unwrap() == 0xaa, "Top should be aa");
}

// ============================================
// OP_SHA256 Tests
// ============================================

#[test]
fn test_sha256_empty() {
    // SHA256("") = e3b0c442... (known value)
    let empty: ByteArray = "";
    let hash = sha256(@empty);
    assert!(hash.len() == 32, "SHA256 should be 32 bytes");
    // First byte of SHA256("") is 0xe3
    assert!(hash.at(0).unwrap() == 0xe3, "First byte should be 0xe3");
    // Last byte is 0x55
    assert!(hash.at(31).unwrap() == 0x55, "Last byte should be 0x55");
}

#[test]
fn test_sha256_abc() {
    // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let mut abc: ByteArray = "";
    abc.append_byte(0x61); // 'a'
    abc.append_byte(0x62); // 'b'
    abc.append_byte(0x63); // 'c'
    let hash = sha256(@abc);
    assert!(hash.len() == 32, "SHA256 should be 32 bytes");
    // First byte is 0xba
    assert!(hash.at(0).unwrap() == 0xba, "First byte should be 0xba");
    // Second byte is 0x78
    assert!(hash.at(1).unwrap() == 0x78, "Second byte should be 0x78");
}

#[test]
fn test_op_sha256_in_script() {
    // Push data, hash it
    let script: Array<u8> = array![
        0x03, 0x61, 0x62, 0x63,  // PUSH_3 "abc"
        OP_SHA256                 // Hash it
    ];
    let mut vm = ScriptVMTrait::new(script);
    let result = vm.execute();
    assert!(result.is_ok(), "SHA256 should succeed");
    assert!(vm.stack.len() == 1, "Should have one element");
    assert!(vm.stack.at(0).len() == 32, "Hash should be 32 bytes");
    assert!(vm.stack.at(0).at(0).unwrap() == 0xba, "First byte should be 0xba");
}

// ============================================
// OP_CHECKSIGADD Tests (simplified)
// ============================================

#[test]
fn test_checksigadd_empty_sig() {
    // Empty signature should not increment counter
    let mut stack: Array<ByteArray> = array![];

    // Empty signature
    let sig: ByteArray = "";
    stack.append(sig);

    // Pubkey (dummy)
    let mut pubkey: ByteArray = "";
    pubkey.append_byte(0x02);
    let mut i: u32 = 0;
    while i < 32 {
        pubkey.append_byte(0xaa);
        i += 1;
    };
    stack.append(pubkey);

    // Counter n=5
    let mut n: ByteArray = "";
    n.append_byte(0x05);
    stack.append(n);

    let script: Array<u8> = array![OP_CHECKSIGADD];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);
    let result = vm.execute();
    assert!(result.is_ok(), "CHECKSIGADD with empty sig should succeed");
    assert!(vm.stack.len() == 1, "Should have one element");
    // Result should be 5 (unchanged)
    assert!(vm.stack.at(0).at(0).unwrap() == 5, "Counter should be unchanged");
}

#[test]
fn test_checksigadd_nonempty_sig() {
    // Non-empty signature should increment counter (simplified: always valid)
    let mut stack: Array<ByteArray> = array![];

    // Non-empty signature (dummy)
    let mut sig: ByteArray = "";
    sig.append_byte(0x30);
    sig.append_byte(0x44);
    stack.append(sig);

    // Pubkey (dummy)
    let mut pubkey: ByteArray = "";
    pubkey.append_byte(0x02);
    let mut i: u32 = 0;
    while i < 32 {
        pubkey.append_byte(0xbb);
        i += 1;
    };
    stack.append(pubkey);

    // Counter n=5
    let mut n: ByteArray = "";
    n.append_byte(0x05);
    stack.append(n);

    let script: Array<u8> = array![OP_CHECKSIGADD];
    let mut vm = ScriptVMTrait::new_with_stack(script, stack);
    let result = vm.execute();
    assert!(result.is_ok(), "CHECKSIGADD with sig should succeed");
    assert!(vm.stack.len() == 1, "Should have one element");
    // Result should be 6 (incremented)
    assert!(vm.stack.at(0).at(0).unwrap() == 6, "Counter should be incremented");
}

// ============================================
// Combined Covenant Tests
// ============================================

#[test]
fn test_cat_sha256_equalverify() {
    // Covenant pattern: CAT two values, hash, verify against expected
    // This is a simplified version of what real OP_CAT covenants do

    // First, compute expected hash of "helloworld"
    let mut hw: ByteArray = "";
    hw.append_byte(0x68); // h
    hw.append_byte(0x65); // e
    hw.append_byte(0x6c); // l
    hw.append_byte(0x6c); // l
    hw.append_byte(0x6f); // o
    hw.append_byte(0x77); // w
    hw.append_byte(0x6f); // o
    hw.append_byte(0x72); // r
    hw.append_byte(0x6c); // l
    hw.append_byte(0x64); // d
    let expected_hash = sha256(@hw);

    // Build stack: [expected_hash, "hello", "world"]
    let mut stack: Array<ByteArray> = array![];
    stack.append(expected_hash);

    let mut hello: ByteArray = "";
    hello.append_byte(0x68);
    hello.append_byte(0x65);
    hello.append_byte(0x6c);
    hello.append_byte(0x6c);
    hello.append_byte(0x6f);
    stack.append(hello);

    let mut world: ByteArray = "";
    world.append_byte(0x77);
    world.append_byte(0x6f);
    world.append_byte(0x72);
    world.append_byte(0x6c);
    world.append_byte(0x64);
    stack.append(world);

    // Script: CAT SHA256 EQUALVERIFY OP_1
    let script: Array<u8> = array![OP_CAT, OP_SHA256, OP_EQUALVERIFY, OP_1];

    let mut vm = ScriptVMTrait::new_with_stack(script, stack);
    let result = vm.execute();
    assert!(result.is_ok(), "CAT SHA256 EQUALVERIFY should succeed");
    assert!(vm.stack.len() == 1, "Should have one element");
}
