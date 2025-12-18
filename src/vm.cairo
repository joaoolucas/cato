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
        ScriptVM { stack: ArrayTrait::new(), bytecode, pc: 0 }
    }

    /// Create a new VM instance with initial stack data
    fn new_with_stack(bytecode: Array<u8>, initial_stack: Array<ByteArray>) -> ScriptVM {
        ScriptVM { stack: initial_stack, bytecode, pc: 0 }
    }

    /// Execute the script until completion or error
    fn execute(ref self: ScriptVM) -> Result<(), VMError> {
        while self.pc < self.bytecode.len() {
            let opcode = *self.bytecode.at(self.pc);
            self.pc += 1;

            let result = match opcode {
                0x00 => self.op_push(),
                0x69 => self.op_verify(),
                0x75 => self.op_drop(),
                0x76 => self.op_dup(),
                0x7e => self.op_cat(),
                0x87 => self.op_equal(),
                0x93 => self.op_add(),
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
