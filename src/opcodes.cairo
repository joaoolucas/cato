/// Bitcoin Script Opcodes for Cato VM
///
/// This module defines the opcodes supported by the Cato Bitcoin Script VM.
/// The opcodes follow Bitcoin's numbering scheme where applicable.

/// OP_0 / OP_FALSE - Push empty array onto the stack
/// Bitcoin opcode: 0x00 (0)
pub const OP_0: u8 = 0x00;
pub const OP_FALSE: u8 = 0x00;

/// OP_ADD - Add two numbers
/// Pops two elements, decodes them as script numbers,
/// adds them, encodes the result, and pushes it back
/// Bitcoin opcode: 0x93 (147)
pub const OP_ADD: u8 = 0x93;

/// OP_CAT - Concatenate two byte arrays (custom/restored opcode)
/// Pops two elements (top=b, second=a), concatenates as a+b, pushes result
/// This opcode was disabled in Bitcoin but is enabled in Cato
/// Bitcoin opcode: 0x7e (126)
pub const OP_CAT: u8 = 0x7e;

/// OP_DUP - Duplicate top stack element
/// Bitcoin opcode: 0x76 (118)
pub const OP_DUP: u8 = 0x76;

/// OP_DROP - Remove top stack element
/// Bitcoin opcode: 0x75 (117)
pub const OP_DROP: u8 = 0x75;

/// OP_EQUAL - Check if two top elements are equal
/// Pushes 1 if equal, 0 otherwise
/// Bitcoin opcode: 0x87 (135)
pub const OP_EQUAL: u8 = 0x87;

/// OP_VERIFY - Fail if top stack element is zero/empty
/// Bitcoin opcode: 0x69 (105)
pub const OP_VERIFY: u8 = 0x69;

/// OP_EQUALVERIFY - OP_EQUAL followed by OP_VERIFY
/// Checks equality and fails if not equal
/// Bitcoin opcode: 0x88 (136)
pub const OP_EQUALVERIFY: u8 = 0x88;

/// OP_1 / OP_TRUE - Push the number 1 onto the stack
/// Bitcoin opcode: 0x51 (81)
pub const OP_1: u8 = 0x51;

/// OP_2 through OP_16 - Push small numbers onto the stack
/// Bitcoin opcodes: 0x52 (82) through 0x60 (96)
pub const OP_2: u8 = 0x52;
pub const OP_3: u8 = 0x53;
pub const OP_4: u8 = 0x54;
pub const OP_5: u8 = 0x55;
pub const OP_6: u8 = 0x56;
pub const OP_7: u8 = 0x57;
pub const OP_8: u8 = 0x58;
pub const OP_9: u8 = 0x59;
pub const OP_10: u8 = 0x5a;
pub const OP_11: u8 = 0x5b;
pub const OP_12: u8 = 0x5c;
pub const OP_13: u8 = 0x5d;
pub const OP_14: u8 = 0x5e;
pub const OP_15: u8 = 0x5f;
pub const OP_16: u8 = 0x60;

/// OP_1NEGATE - Push -1 onto the stack
/// Bitcoin opcode: 0x4f (79)
pub const OP_1NEGATE: u8 = 0x4f;

/// OP_TOALTSTACK - Move top item to alt stack
/// Bitcoin opcode: 0x6b (107)
pub const OP_TOALTSTACK: u8 = 0x6b;

/// OP_FROMALTSTACK - Move top item from alt stack to main stack
/// Bitcoin opcode: 0x6c (108)
pub const OP_FROMALTSTACK: u8 = 0x6c;

/// OP_ROLL - Move item n back in stack to top
/// Bitcoin opcode: 0x7a (122)
pub const OP_ROLL: u8 = 0x7a;

/// OP_SHA256 - SHA256 hash of top element
/// Bitcoin opcode: 0xa8 (168)
pub const OP_SHA256: u8 = 0xa8;

/// OP_HASH160 - RIPEMD160(SHA256(x)) of top element
/// Bitcoin opcode: 0xa9 (169)
pub const OP_HASH160: u8 = 0xa9;

/// OP_CHECKSIG - Verify signature against public key
/// Bitcoin opcode: 0xac (172)
pub const OP_CHECKSIG: u8 = 0xac;

/// OP_CHECKSIGADD - Taproot: verify sig and add to counter
/// Bitcoin opcode: 0xba (186)
pub const OP_CHECKSIGADD: u8 = 0xba;

/// OP_PICK - Copy item n back in stack to top
/// Bitcoin opcode: 0x79 (121)
pub const OP_PICK: u8 = 0x79;

/// OP_ROT - Rotate top 3 items: x1 x2 x3 -> x2 x3 x1
/// Bitcoin opcode: 0x7b (123)
pub const OP_ROT: u8 = 0x7b;

/// OP_SWAP - Swap top two items
/// Bitcoin opcode: 0x7c (124)
pub const OP_SWAP: u8 = 0x7c;

/// OP_SIZE - Push the size of top element (without removing it)
/// Bitcoin opcode: 0x82 (130)
pub const OP_SIZE: u8 = 0x82;

/// OP_OVER - Copy second-to-top item to top
/// Bitcoin opcode: 0x78 (120)
pub const OP_OVER: u8 = 0x78;

/// OP_PUSHDATA1 - Push data with 1-byte length prefix
/// Bitcoin opcode: 0x4c (76)
pub const OP_PUSHDATA1: u8 = 0x4c;

/// OP_CHECKSIGVERIFY - OP_CHECKSIG followed by OP_VERIFY
/// Bitcoin opcode: 0xad (173)
pub const OP_CHECKSIGVERIFY: u8 = 0xad;

/// OP_CHECKLOCKTIMEVERIFY (OP_CLTV) - Check if timelock has expired
/// Marks transaction invalid if the top stack item is greater than nLockTime
/// Bitcoin opcode: 0xb1 (177)
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;

/// OP_CHECKSEQUENCEVERIFY (OP_CSV) - Check relative timelock
/// Bitcoin opcode: 0xb2 (178)
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;

/// OP_NOP - No operation
/// Bitcoin opcode: 0x61 (97)
pub const OP_NOP: u8 = 0x61;
