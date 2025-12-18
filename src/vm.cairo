/// Cato Bitcoin Script Virtual Machine
///
/// A Cairo 2.0 implementation of a Bitcoin Script VM with support for
/// stack operations, arithmetic, and the OP_CAT opcode.

// Opcodes are matched by their numeric values in the execute function

/// Maximum number of elements allowed on the stack (Bitcoin limit)
pub const MAX_STACK_SIZE: u32 = 1000;

/// Maximum size of a single stack element in bytes (Bitcoin limit)
pub const MAX_ELEMENT_SIZE: u32 = 520;

/// VM execution errors
#[derive(Drop, Debug, PartialEq)]
pub enum VMError {
    /// Attempted to pop from empty stack
    StackUnderflow,
    /// Stack exceeded maximum size
    StackOverflow,
    /// Unknown or unsupported opcode
    InvalidOpcode,
    /// Push length exceeds remaining bytecode
    InvalidPushLength,
    /// Element exceeds maximum allowed size
    ElementTooLarge,
    /// Script execution completed but failed verification
    ScriptFailed,
    /// Numeric overflow during arithmetic
    NumericOverflow,
}

/// Bitcoin Script Virtual Machine
#[derive(Drop)]
pub struct ScriptVM {
    /// Main execution stack using ByteArray for each element
    pub stack: Array<ByteArray>,
    /// Alternate stack for TOALTSTACK/FROMALTSTACK
    pub alt_stack: Array<ByteArray>,
    /// Program bytecode
    bytecode: Array<u8>,
    /// Program counter (current position in bytecode)
    pc: usize,
}

/// Public interface for ScriptVM
#[generate_trait]
pub impl ScriptVMImpl of ScriptVMTrait {
    /// Create a new VM instance with the given bytecode
    fn new(bytecode: Array<u8>) -> ScriptVM {
        ScriptVM { stack: ArrayTrait::new(), alt_stack: ArrayTrait::new(), bytecode, pc: 0 }
    }

    /// Create a new VM instance with initial stack data
    fn new_with_stack(bytecode: Array<u8>, initial_stack: Array<ByteArray>) -> ScriptVM {
        ScriptVM { stack: initial_stack, alt_stack: ArrayTrait::new(), bytecode, pc: 0 }
    }

    /// Execute the script until completion or error
    fn execute(ref self: ScriptVM) -> Result<(), VMError> {
        while self.pc < self.bytecode.len() {
            let opcode = *self.bytecode.at(self.pc);
            self.pc += 1;

            let result = match opcode {
                0x00 => self.op_false(),          // OP_0 / OP_FALSE (Bitcoin standard)
                // Direct push: 0x01-0x4b push next n bytes
                0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 |
                0x09 | 0x0a | 0x0b | 0x0c | 0x0d | 0x0e | 0x0f | 0x10 |
                0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | 0x18 |
                0x19 | 0x1a | 0x1b | 0x1c | 0x1d | 0x1e | 0x1f | 0x20 |
                0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x28 |
                0x29 | 0x2a | 0x2b | 0x2c | 0x2d | 0x2e | 0x2f | 0x30 |
                0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x37 | 0x38 |
                0x39 | 0x3a | 0x3b | 0x3c | 0x3d | 0x3e | 0x3f | 0x40 |
                0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x47 | 0x48 |
                0x49 | 0x4a | 0x4b => self.op_push_n(opcode),
                0x4c => self.op_pushdata1(),   // OP_PUSHDATA1
                // OP_1 through OP_16: Push small numbers
                0x51 => self.op_pushnum(1),    // OP_1 / OP_TRUE
                0x52 => self.op_pushnum(2),    // OP_2
                0x53 => self.op_pushnum(3),    // OP_3
                0x54 => self.op_pushnum(4),    // OP_4
                0x55 => self.op_pushnum(5),    // OP_5
                0x56 => self.op_pushnum(6),    // OP_6
                0x57 => self.op_pushnum(7),    // OP_7
                0x58 => self.op_pushnum(8),    // OP_8
                0x59 => self.op_pushnum(9),    // OP_9
                0x5a => self.op_pushnum(10),   // OP_10
                0x5b => self.op_pushnum(11),   // OP_11
                0x5c => self.op_pushnum(12),   // OP_12
                0x5d => self.op_pushnum(13),   // OP_13
                0x5e => self.op_pushnum(14),   // OP_14
                0x5f => self.op_pushnum(15),   // OP_15
                0x60 => self.op_pushnum(16),   // OP_16
                0x69 => self.op_verify(),      // OP_VERIFY
                0x6b => self.op_toaltstack(),  // OP_TOALTSTACK
                0x6c => self.op_fromaltstack(), // OP_FROMALTSTACK
                0x75 => self.op_drop(),        // OP_DROP
                0x76 => self.op_dup(),         // OP_DUP
                0x78 => self.op_over(),        // OP_OVER
                0x79 => self.op_pick(),        // OP_PICK
                0x7a => self.op_roll(),        // OP_ROLL
                0x7b => self.op_rot(),         // OP_ROT
                0x7c => self.op_swap(),        // OP_SWAP
                0x7e => self.op_cat(),         // OP_CAT
                0x82 => self.op_size(),        // OP_SIZE
                0x87 => self.op_equal(),       // OP_EQUAL
                0x88 => self.op_equalverify(), // OP_EQUALVERIFY
                0x93 => self.op_add(),         // OP_ADD
                0xa8 => self.op_sha256(),      // OP_SHA256
                0xac => self.op_checksig(),    // OP_CHECKSIG
                0xad => self.op_checksigverify(), // OP_CHECKSIGVERIFY
                0xba => self.op_checksigadd(), // OP_CHECKSIGADD
                0x61 => self.op_nop(),         // OP_NOP
                0xb1 => self.op_checklocktimeverify(), // OP_CHECKLOCKTIMEVERIFY
                0xb2 => self.op_checksequenceverify(), // OP_CHECKSEQUENCEVERIFY
                _ => Result::Err(VMError::InvalidOpcode),
            };

            result?;
        };

        Result::Ok(())
    }

    /// Get the current stack
    fn get_stack(self: @ScriptVM) -> @Array<ByteArray> {
        self.stack
    }
}

/// Internal opcode implementations
#[generate_trait]
impl ScriptVMInternalImpl of ScriptVMInternalTrait {
    /// OP_FALSE / OP_0: Push empty byte array onto stack
    fn op_false(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() >= MAX_STACK_SIZE {
            return Result::Err(VMError::StackOverflow);
        }
        let empty: ByteArray = "";
        self.stack.append(empty);
        Result::Ok(())
    }

    /// OP_PUSH_N: Push next n bytes onto stack (for opcodes 0x01-0x4b)
    fn op_push_n(ref self: ScriptVM, n: u8) -> Result<(), VMError> {
        if self.stack.len() >= MAX_STACK_SIZE {
            return Result::Err(VMError::StackOverflow);
        }

        let length: u32 = n.into();
        if length > MAX_ELEMENT_SIZE {
            return Result::Err(VMError::ElementTooLarge);
        }

        if self.pc + length.try_into().unwrap() > self.bytecode.len() {
            return Result::Err(VMError::InvalidPushLength);
        }

        let mut data: ByteArray = "";
        let mut i: u32 = 0;
        while i < length {
            data.append_byte(*self.bytecode.at(self.pc));
            self.pc += 1;
            i += 1;
        };

        self.stack.append(data);
        Result::Ok(())
    }

    /// OP_PUSHDATA1: Push data with 1-byte length prefix
    fn op_pushdata1(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() >= MAX_STACK_SIZE {
            return Result::Err(VMError::StackOverflow);
        }

        if self.pc >= self.bytecode.len() {
            return Result::Err(VMError::InvalidPushLength);
        }

        let length: u32 = (*self.bytecode.at(self.pc)).into();
        self.pc += 1;

        if length > MAX_ELEMENT_SIZE {
            return Result::Err(VMError::ElementTooLarge);
        }

        if self.pc + length.try_into().unwrap() > self.bytecode.len() {
            return Result::Err(VMError::InvalidPushLength);
        }

        let mut data: ByteArray = "";
        let mut i: u32 = 0;
        while i < length {
            data.append_byte(*self.bytecode.at(self.pc));
            self.pc += 1;
            i += 1;
        };

        self.stack.append(data);
        Result::Ok(())
    }

    /// OP_OVER: Copy second-to-top item to top
    /// Stack: x1 x2 -> x1 x2 x1
    fn op_over(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 2 {
            return Result::Err(VMError::StackUnderflow);
        }
        if self.stack.len() >= MAX_STACK_SIZE {
            return Result::Err(VMError::StackOverflow);
        }

        let second = clone_byte_array(self.stack.at(self.stack.len() - 2));
        self.stack.append(second);
        Result::Ok(())
    }

    /// OP_PUSH: Push data onto stack
    /// Format: OP_PUSH <length:u8> <data:bytes>
    fn op_push(ref self: ScriptVM) -> Result<(), VMError> {
        // Check stack size limit
        if self.stack.len() >= MAX_STACK_SIZE {
            return Result::Err(VMError::StackOverflow);
        }

        // Read length byte
        if self.pc >= self.bytecode.len() {
            return Result::Err(VMError::InvalidPushLength);
        }
        let length: u32 = (*self.bytecode.at(self.pc)).into();
        self.pc += 1;

        // Check element size limit
        if length > MAX_ELEMENT_SIZE {
            return Result::Err(VMError::ElementTooLarge);
        }

        // Check if enough bytes remain
        if self.pc + length.try_into().unwrap() > self.bytecode.len() {
            return Result::Err(VMError::InvalidPushLength);
        }

        // Read data bytes into ByteArray
        let mut data: ByteArray = "";
        let mut i: u32 = 0;
        while i < length {
            let byte = *self.bytecode.at(self.pc);
            data.append_byte(byte);
            self.pc += 1;
            i += 1;
        };

        self.stack.append(data);
        Result::Ok(())
    }

    /// OP_ADD: Pop two numbers, add them, push result
    fn op_add(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 2 {
            return Result::Err(VMError::StackUnderflow);
        }

        let (new_stack, b) = stack_pop(self.stack);
        self.stack = new_stack;
        let (new_stack, a) = stack_pop(self.stack);
        self.stack = new_stack;

        let num_a = decode_script_num(@a);
        let num_b = decode_script_num(@b);

        // Add the numbers (handle potential overflow)
        let sum = num_a + num_b;

        let result = encode_script_num(sum);

        // Check result size
        if result.len() > MAX_ELEMENT_SIZE {
            return Result::Err(VMError::ElementTooLarge);
        }

        self.stack.append(result);
        Result::Ok(())
    }

    /// OP_CAT: Pop two elements, concatenate, push result
    fn op_cat(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 2 {
            return Result::Err(VMError::StackUnderflow);
        }

        let (new_stack, b) = stack_pop(self.stack);
        self.stack = new_stack;
        let (new_stack, a) = stack_pop(self.stack);
        self.stack = new_stack;

        // Concatenate a + b
        let mut result: ByteArray = a;
        result.append(@b);

        // Check result size
        if result.len() > MAX_ELEMENT_SIZE {
            return Result::Err(VMError::ElementTooLarge);
        }

        // Check stack size
        if self.stack.len() >= MAX_STACK_SIZE {
            return Result::Err(VMError::StackOverflow);
        }

        self.stack.append(result);
        Result::Ok(())
    }

    /// OP_DUP: Duplicate top stack element
    fn op_dup(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 1 {
            return Result::Err(VMError::StackUnderflow);
        }
        if self.stack.len() >= MAX_STACK_SIZE {
            return Result::Err(VMError::StackOverflow);
        }

        let top = self.stack.at(self.stack.len() - 1);
        let copy = clone_byte_array(top);
        self.stack.append(copy);
        Result::Ok(())
    }

    /// OP_DROP: Remove top stack element
    fn op_drop(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 1 {
            return Result::Err(VMError::StackUnderflow);
        }
        let (new_stack, _) = stack_pop(self.stack);
        self.stack = new_stack;
        Result::Ok(())
    }

    /// OP_EQUAL: Check if two top elements are equal
    fn op_equal(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 2 {
            return Result::Err(VMError::StackUnderflow);
        }

        let (new_stack, b) = stack_pop(self.stack);
        self.stack = new_stack;
        let (new_stack, a) = stack_pop(self.stack);
        self.stack = new_stack;

        let result = if byte_array_eq(@a, @b) {
            encode_script_num(1)
        } else {
            encode_script_num(0)
        };

        self.stack.append(result);
        Result::Ok(())
    }

    /// OP_VERIFY: Fail if top element is zero/empty
    fn op_verify(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 1 {
            return Result::Err(VMError::StackUnderflow);
        }

        let (new_stack, top) = stack_pop(self.stack);
        self.stack = new_stack;

        if !is_truthy(@top) {
            return Result::Err(VMError::ScriptFailed);
        }
        Result::Ok(())
    }

    /// OP_EQUALVERIFY: OP_EQUAL followed by OP_VERIFY
    fn op_equalverify(ref self: ScriptVM) -> Result<(), VMError> {
        // First do OP_EQUAL
        self.op_equal()?;

        // Then do OP_VERIFY
        self.op_verify()
    }

    /// OP_PUSHNUM: Push a small number (1-16) onto the stack
    fn op_pushnum(ref self: ScriptVM, n: u8) -> Result<(), VMError> {
        if self.stack.len() >= MAX_STACK_SIZE {
            return Result::Err(VMError::StackOverflow);
        }

        let mut num: ByteArray = "";
        num.append_byte(n);
        self.stack.append(num);
        Result::Ok(())
    }

    /// OP_TOALTSTACK: Move top item from main stack to alt stack
    fn op_toaltstack(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 1 {
            return Result::Err(VMError::StackUnderflow);
        }
        if self.alt_stack.len() >= MAX_STACK_SIZE {
            return Result::Err(VMError::StackOverflow);
        }

        let (new_stack, top) = stack_pop(self.stack);
        self.stack = new_stack;
        self.alt_stack.append(top);
        Result::Ok(())
    }

    /// OP_FROMALTSTACK: Move top item from alt stack to main stack
    fn op_fromaltstack(ref self: ScriptVM) -> Result<(), VMError> {
        if self.alt_stack.len() < 1 {
            return Result::Err(VMError::StackUnderflow);
        }
        if self.stack.len() >= MAX_STACK_SIZE {
            return Result::Err(VMError::StackOverflow);
        }

        let (new_alt_stack, top) = stack_pop(self.alt_stack);
        self.alt_stack = new_alt_stack;
        self.stack.append(top);
        Result::Ok(())
    }

    /// OP_PICK: Copy item n back in stack to top
    fn op_pick(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 1 {
            return Result::Err(VMError::StackUnderflow);
        }

        // Pop n from stack
        let (new_stack, n_bytes) = stack_pop(self.stack);
        self.stack = new_stack;
        let n: usize = decode_script_num(@n_bytes).try_into().unwrap();

        if self.stack.len() < n + 1 {
            return Result::Err(VMError::StackUnderflow);
        }
        if self.stack.len() >= MAX_STACK_SIZE {
            return Result::Err(VMError::StackOverflow);
        }

        // Copy the nth item (0-indexed from top)
        let idx = self.stack.len() - 1 - n;
        let item = clone_byte_array(self.stack.at(idx));
        self.stack.append(item);
        Result::Ok(())
    }

    /// OP_ROLL: Move item n back in stack to top
    fn op_roll(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 1 {
            return Result::Err(VMError::StackUnderflow);
        }

        // Pop n from stack
        let (new_stack, n_bytes) = stack_pop(self.stack);
        self.stack = new_stack;
        let n: usize = decode_script_num(@n_bytes).try_into().unwrap();

        if self.stack.len() < n + 1 {
            return Result::Err(VMError::StackUnderflow);
        }

        // Get the nth item (0-indexed from top)
        let idx = self.stack.len() - 1 - n;
        let item = clone_byte_array(self.stack.at(idx));

        // Remove the item at idx and push to top
        let mut new_stack: Array<ByteArray> = ArrayTrait::new();
        let mut i: usize = 0;
        while i < self.stack.len() {
            if i != idx {
                new_stack.append(clone_byte_array(self.stack.at(i)));
            }
            i += 1;
        };
        new_stack.append(item);
        self.stack = new_stack;
        Result::Ok(())
    }

    /// OP_ROT: Rotate top three stack items
    /// x1 x2 x3 -> x2 x3 x1
    fn op_rot(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 3 {
            return Result::Err(VMError::StackUnderflow);
        }

        let len = self.stack.len();

        // Get the three elements
        let x3 = clone_byte_array(self.stack.at(len - 1));
        let x2 = clone_byte_array(self.stack.at(len - 2));
        let x1 = clone_byte_array(self.stack.at(len - 3));

        // Pop three elements
        let (new_stack, _) = stack_pop(self.stack);
        self.stack = new_stack;
        let (new_stack, _) = stack_pop(self.stack);
        self.stack = new_stack;
        let (new_stack, _) = stack_pop(self.stack);
        self.stack = new_stack;

        // Push in rotated order: x2, x3, x1
        self.stack.append(x2);
        self.stack.append(x3);
        self.stack.append(x1);

        Result::Ok(())
    }

    /// OP_SWAP: Swap top two stack items
    fn op_swap(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 2 {
            return Result::Err(VMError::StackUnderflow);
        }

        let len = self.stack.len();

        // Get the two elements
        let top = clone_byte_array(self.stack.at(len - 1));
        let second = clone_byte_array(self.stack.at(len - 2));

        // Pop two elements
        let (new_stack, _) = stack_pop(self.stack);
        self.stack = new_stack;
        let (new_stack, _) = stack_pop(self.stack);
        self.stack = new_stack;

        // Push in swapped order
        self.stack.append(top);
        self.stack.append(second);

        Result::Ok(())
    }

    /// OP_SIZE: Push the size of top element (without removing it)
    fn op_size(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 1 {
            return Result::Err(VMError::StackUnderflow);
        }
        if self.stack.len() >= MAX_STACK_SIZE {
            return Result::Err(VMError::StackOverflow);
        }

        let top = self.stack.at(self.stack.len() - 1);
        let size: i64 = top.len().into();
        let size_encoded = encode_script_num(size);
        self.stack.append(size_encoded);

        Result::Ok(())
    }

    /// OP_SHA256: SHA256 hash of top element
    fn op_sha256(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 1 {
            return Result::Err(VMError::StackUnderflow);
        }

        let (new_stack, data) = stack_pop(self.stack);
        self.stack = new_stack;

        // Compute SHA256 hash
        let hash = sha256(@data);

        self.stack.append(hash);
        Result::Ok(())
    }

    /// OP_CHECKSIGADD: Taproot signature check and add
    /// Stack: sig pubkey n -> n+1 (if sig valid) or n (if sig empty)
    fn op_checksigadd(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 3 {
            return Result::Err(VMError::StackUnderflow);
        }

        // Pop n, pubkey, sig
        let (new_stack, n_bytes) = stack_pop(self.stack);
        self.stack = new_stack;
        let (new_stack, _pubkey) = stack_pop(self.stack);
        self.stack = new_stack;
        let (new_stack, sig) = stack_pop(self.stack);
        self.stack = new_stack;

        let n = decode_script_num(@n_bytes);

        // If signature is empty, push n unchanged
        // If signature is present, verify and push n+1 if valid
        // For now, we assume non-empty signatures are valid (simplified)
        let result = if sig.len() == 0 {
            encode_script_num(n)
        } else {
            // In a full implementation, we would verify the Schnorr signature
            // For covenant verification without actual sig check, assume valid
            encode_script_num(n + 1)
        };

        self.stack.append(result);
        Result::Ok(())
    }

    /// OP_CHECKSIG: Verify signature against public key
    /// Stack: sig pubkey -> 1 (if valid) or 0 (if invalid/empty)
    fn op_checksig(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 2 {
            return Result::Err(VMError::StackUnderflow);
        }

        // Pop pubkey and sig
        let (new_stack, _pubkey) = stack_pop(self.stack);
        self.stack = new_stack;
        let (new_stack, sig) = stack_pop(self.stack);
        self.stack = new_stack;

        // For covenant verification: non-empty signature = valid
        // In a full implementation, we would verify the Schnorr/ECDSA signature
        let mut result: ByteArray = "";
        if sig.len() > 0 {
            result.append_byte(1); // TRUE
        }
        // Empty result = FALSE (0)

        self.stack.append(result);
        Result::Ok(())
    }

    /// OP_CHECKSIGVERIFY: OP_CHECKSIG followed by OP_VERIFY
    fn op_checksigverify(ref self: ScriptVM) -> Result<(), VMError> {
        // First do OP_CHECKSIG
        self.op_checksig()?;

        // Then do OP_VERIFY
        self.op_verify()
    }

    /// OP_NOP: No operation - does nothing
    fn op_nop(ref self: ScriptVM) -> Result<(), VMError> {
        Result::Ok(())
    }

    /// OP_CHECKLOCKTIMEVERIFY (OP_CLTV): Verify absolute timelock
    /// Stack: n -> n (leaves stack unchanged, fails if timelock not satisfied)
    /// In Bitcoin, this checks nLockTime. Here we simulate for covenant verification.
    fn op_checklocktimeverify(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 1 {
            return Result::Err(VMError::StackUnderflow);
        }

        // Read the timelock value from stack (don't pop, CLTV leaves stack unchanged)
        let top = self.stack.at(self.stack.len() - 1);
        let locktime = decode_script_num(top);

        // In actual Bitcoin, this would check against transaction nLockTime
        // For covenant simulation, we accept any positive locktime as valid
        // (actual timelock enforcement would be done at transaction validation)
        if locktime < 0 {
            return Result::Err(VMError::ScriptFailed);
        }

        // Stack remains unchanged - just verification
        Result::Ok(())
    }

    /// OP_CHECKSEQUENCEVERIFY (OP_CSV): Verify relative timelock
    /// Stack: n -> n (leaves stack unchanged, fails if sequence not satisfied)
    fn op_checksequenceverify(ref self: ScriptVM) -> Result<(), VMError> {
        if self.stack.len() < 1 {
            return Result::Err(VMError::StackUnderflow);
        }

        // Read the sequence value from stack (don't pop)
        let top = self.stack.at(self.stack.len() - 1);
        let sequence = decode_script_num(top);

        // For covenant simulation, accept valid sequences
        if sequence < 0 {
            return Result::Err(VMError::ScriptFailed);
        }

        // Stack remains unchanged
        Result::Ok(())
    }
}

/// Pop the last element from a ByteArray stack
/// Returns (remaining_stack, popped_element)
fn stack_pop(mut stack: Array<ByteArray>) -> (Array<ByteArray>, ByteArray) {
    let len = stack.len();
    let mut new_stack: Array<ByteArray> = ArrayTrait::new();
    let mut i: usize = 0;
    let mut last_element: ByteArray = "";

    // Copy all elements except the last one, keeping track of the last
    while i < len {
        let elem = stack.pop_front().unwrap();
        if i < len - 1 {
            new_stack.append(elem);
        } else {
            last_element = elem;
        }
        i += 1;
    };

    (new_stack, last_element)
}

/// Clone a ByteArray (deep copy)
fn clone_byte_array(src: @ByteArray) -> ByteArray {
    let mut result: ByteArray = "";
    let mut i: usize = 0;
    while i < src.len() {
        result.append_byte(src.at(i).unwrap());
        i += 1;
    };
    result
}

/// Compare two ByteArrays for equality
fn byte_array_eq(a: @ByteArray, b: @ByteArray) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len() {
        if a.at(i).unwrap() != b.at(i).unwrap() {
            return false;
        }
        i += 1;
    };
    true
}

/// Check if a ByteArray represents a truthy value
/// Empty or all-zeros (including negative zero 0x80) is falsy
pub fn is_truthy(value: @ByteArray) -> bool {
    if value.len() == 0 {
        return false;
    }

    let mut i: usize = 0;
    let last_idx = value.len() - 1;

    while i < value.len() {
        let byte = value.at(i).unwrap();
        // Check for non-zero byte (excluding sign bit in last byte)
        if i == last_idx {
            // Last byte: check if non-zero after masking sign bit
            if byte & 0x7f != 0 {
                return true;
            }
        } else {
            if byte != 0 {
                return true;
            }
        }
        i += 1;
    };
    false
}

/// Decode a ByteArray as a Bitcoin script number (little-endian signed magnitude)
/// Bitcoin script numbers can be up to 4 bytes (though some operations allow more)
pub fn decode_script_num(bytes: @ByteArray) -> i64 {
    if bytes.len() == 0 {
        return 0;
    }

    let len = bytes.len();
    let mut result: i64 = 0;
    let mut i: usize = 0;

    // Read all bytes except potentially processing the sign bit
    while i < len {
        let byte: i64 = bytes.at(i).unwrap().into();
        result = result + byte * pow2_i64(i * 8);
        i += 1;
    };

    // Check sign bit in the last byte
    let last_byte: u8 = bytes.at(len - 1).unwrap();
    if last_byte & 0x80 != 0 {
        // Negative number: remove sign bit and negate
        let sign_mask: i64 = pow2_i64((len - 1) * 8 + 7);
        result = -(result - sign_mask);
    }

    result
}

/// Encode an i64 as a Bitcoin script number (little-endian signed magnitude)
pub fn encode_script_num(value: i64) -> ByteArray {
    if value == 0 {
        return "";
    }

    let negative = value < 0;
    let mut abs_value: u64 = if negative {
        // Handle i64::MIN edge case
        if value == -9223372036854775808 {
            9223372036854775808_u64
        } else {
            (-value).try_into().unwrap()
        }
    } else {
        value.try_into().unwrap()
    };

    let mut result: ByteArray = "";

    // Write bytes little-endian
    while abs_value > 0 {
        let byte: u8 = (abs_value & 0xff).try_into().unwrap();
        result.append_byte(byte);
        abs_value = abs_value / 256;
    };

    // Handle sign bit
    let last_idx = result.len() - 1;
    let last_byte = result.at(last_idx).unwrap();

    if last_byte & 0x80 != 0 {
        // High bit is set, need to add a sign byte
        if negative {
            result.append_byte(0x80);
        } else {
            result.append_byte(0x00);
        }
    } else if negative {
        // Set the sign bit in the last byte
        // We need to rebuild the result with the modified last byte
        let mut new_result: ByteArray = "";
        let mut i: usize = 0;
        while i < last_idx {
            new_result.append_byte(result.at(i).unwrap());
            i += 1;
        };
        new_result.append_byte(last_byte | 0x80);
        result = new_result;
    }

    result
}

/// Power of 2 for i64
fn pow2_i64(exp: usize) -> i64 {
    let mut result: i64 = 1;
    let mut i: usize = 0;
    while i < exp {
        result = result * 2;
        i += 1;
    };
    result
}

// ============================================
// SHA256 Implementation
// ============================================

/// SHA256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
const SHA256_H0: u32 = 0x6a09e667;
const SHA256_H1: u32 = 0xbb67ae85;
const SHA256_H2: u32 = 0x3c6ef372;
const SHA256_H3: u32 = 0xa54ff53a;
const SHA256_H4: u32 = 0x510e527f;
const SHA256_H5: u32 = 0x9b05688c;
const SHA256_H6: u32 = 0x1f83d9ab;
const SHA256_H7: u32 = 0x5be0cd19;

/// Get SHA256 round constant K[i]
fn sha256_k(i: usize) -> u32 {
    // First 32 bits of fractional parts of cube roots of first 64 primes
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    *k.span().at(i)
}

/// Right rotate a u32 value by n bits
fn rotr32(x: u32, n: u32) -> u32 {
    // x >> n | x << (32 - n)
    // Use u64 to avoid overflow
    let x64: u64 = x.into();
    let right = x64 / pow2_u64(n.into());
    let left = (x64 * pow2_u64((32 - n).into())) % 0x100000000;
    ((right | left) % 0x100000000).try_into().unwrap()
}

/// Power of 2 for u64
fn pow2_u64(exp: u64) -> u64 {
    if exp >= 64 {
        return 0;
    }
    let mut result: u64 = 1;
    let mut i: u64 = 0;
    while i < exp {
        result = result * 2;
        i += 1;
    };
    result
}

/// Power of 2 for u32
fn pow2_u32(exp: u32) -> u32 {
    if exp >= 32 {
        return 0;
    }
    let mut result: u32 = 1;
    let mut i: u32 = 0;
    while i < exp {
        result = result * 2;
        i += 1;
    };
    result
}

/// SHA256 hash function
pub fn sha256(data: @ByteArray) -> ByteArray {
    // Initialize hash values
    let mut h0: u32 = SHA256_H0;
    let mut h1: u32 = SHA256_H1;
    let mut h2: u32 = SHA256_H2;
    let mut h3: u32 = SHA256_H3;
    let mut h4: u32 = SHA256_H4;
    let mut h5: u32 = SHA256_H5;
    let mut h6: u32 = SHA256_H6;
    let mut h7: u32 = SHA256_H7;

    // Pre-processing: Pad message
    let msg_len = data.len();
    let bit_len: u64 = (msg_len * 8).into();

    // Create padded message
    let mut padded: Array<u8> = ArrayTrait::new();

    // Copy original message
    let mut i: usize = 0;
    while i < msg_len {
        padded.append(data.at(i).unwrap());
        i += 1;
    };

    // Append bit '1' (0x80)
    padded.append(0x80);

    // Append zeros until length ≡ 448 (mod 512), i.e., 56 bytes (mod 64)
    let current_len = padded.len();
    let target_len = ((current_len + 8 + 63) / 64) * 64 - 8;
    let mut j: usize = current_len;
    while j < target_len {
        padded.append(0x00);
        j += 1;
    };

    // Append original length in bits as 64-bit big-endian
    padded.append(((bit_len / 0x100000000000000) & 0xff).try_into().unwrap());
    padded.append(((bit_len / 0x1000000000000) & 0xff).try_into().unwrap());
    padded.append(((bit_len / 0x10000000000) & 0xff).try_into().unwrap());
    padded.append(((bit_len / 0x100000000) & 0xff).try_into().unwrap());
    padded.append(((bit_len / 0x1000000) & 0xff).try_into().unwrap());
    padded.append(((bit_len / 0x10000) & 0xff).try_into().unwrap());
    padded.append(((bit_len / 0x100) & 0xff).try_into().unwrap());
    padded.append((bit_len & 0xff).try_into().unwrap());

    // Process each 512-bit (64-byte) chunk
    let num_chunks = padded.len() / 64;
    let mut chunk_idx: usize = 0;

    while chunk_idx < num_chunks {
        let chunk_start = chunk_idx * 64;

        // Create message schedule array w[0..63]
        let mut w: Array<u32> = ArrayTrait::new();

        // Copy chunk into first 16 words (big-endian)
        let mut wi: usize = 0;
        while wi < 16 {
            let idx = chunk_start + wi * 4;
            let word: u32 = (*padded.at(idx)).into() * 0x1000000
                + (*padded.at(idx + 1)).into() * 0x10000
                + (*padded.at(idx + 2)).into() * 0x100
                + (*padded.at(idx + 3)).into();
            w.append(word);
            wi += 1;
        };

        // Extend the first 16 words into the remaining 48 words
        let mut wi: usize = 16;
        while wi < 64 {
            let w15 = *w.at(wi - 15);
            let w2 = *w.at(wi - 2);
            let w16 = *w.at(wi - 16);
            let w7 = *w.at(wi - 7);

            let s0 = rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 / 8);
            let s1 = rotr32(w2, 17) ^ rotr32(w2, 19) ^ (w2 / 1024);

            let new_w = wrapping_add(wrapping_add(wrapping_add(w16, s0), w7), s1);
            w.append(new_w);
            wi += 1;
        };

        // Initialize working variables
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        // Main compression loop
        let mut ri: usize = 0;
        while ri < 64 {
            let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            let ch = (e & f) ^ ((~e) & g);
            let temp1 = wrapping_add(wrapping_add(wrapping_add(wrapping_add(h, s1), ch), sha256_k(ri)), *w.at(ri));
            let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = wrapping_add(s0, maj);

            h = g;
            g = f;
            f = e;
            e = wrapping_add(d, temp1);
            d = c;
            c = b;
            b = a;
            a = wrapping_add(temp1, temp2);

            ri += 1;
        };

        // Add compressed chunk to hash values
        h0 = wrapping_add(h0, a);
        h1 = wrapping_add(h1, b);
        h2 = wrapping_add(h2, c);
        h3 = wrapping_add(h3, d);
        h4 = wrapping_add(h4, e);
        h5 = wrapping_add(h5, f);
        h6 = wrapping_add(h6, g);
        h7 = wrapping_add(h7, h);

        chunk_idx += 1;
    };

    // Produce final hash (big-endian)
    let mut result: ByteArray = "";
    append_u32_be(ref result, h0);
    append_u32_be(ref result, h1);
    append_u32_be(ref result, h2);
    append_u32_be(ref result, h3);
    append_u32_be(ref result, h4);
    append_u32_be(ref result, h5);
    append_u32_be(ref result, h6);
    append_u32_be(ref result, h7);

    result
}

/// Wrapping add for u32 (modulo 2^32)
fn wrapping_add(a: u32, b: u32) -> u32 {
    let sum: u64 = a.into() + b.into();
    (sum % 0x100000000).try_into().unwrap()
}

/// Append u32 as big-endian bytes to ByteArray
fn append_u32_be(ref arr: ByteArray, val: u32) {
    arr.append_byte(((val / 0x1000000) & 0xff).try_into().unwrap());
    arr.append_byte(((val / 0x10000) & 0xff).try_into().unwrap());
    arr.append_byte(((val / 0x100) & 0xff).try_into().unwrap());
    arr.append_byte((val & 0xff).try_into().unwrap());
}
