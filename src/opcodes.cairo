/// Bitcoin Script Opcodes for Cato VM
///
/// This module defines the opcodes supported by the Cato Bitcoin Script VM.
/// The opcodes follow Bitcoin's numbering scheme where applicable.

/// OP_PUSH - Push data onto the stack
/// Format: OP_PUSH <length:u8> <data:bytes>
/// Pushes `length` bytes of data onto the stack
pub const OP_PUSH: u8 = 0x00;

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
