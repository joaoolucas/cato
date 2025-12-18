/// Covenant Module for Cato Bitcoin Script VM
///
/// A Covenant encapsulates a Bitcoin Script that can be verified against
/// input data. The script must execute successfully and leave a truthy
/// (non-zero) value on the stack to pass verification.

use crate::vm::{ScriptVMTrait, VMError, is_truthy};

/// A Covenant represents a script that must be satisfied
#[derive(Drop)]
pub struct Covenant {
    /// The script bytecode that defines the covenant conditions
    pub script: Array<u8>,
}

/// Covenant implementation
#[generate_trait]
pub impl CovenantImpl of CovenantTrait {
    /// Create a new covenant with the given script
    fn new(script: Array<u8>) -> Covenant {
        Covenant { script }
    }

    /// Verify the covenant against input data
    /// Returns true if:
    /// 1. The script executes without errors
    /// 2. Exactly one element remains on the stack
    /// 3. That element is truthy (non-zero, non-empty)
    fn verify(self: @Covenant, input_data: Array<ByteArray>) -> bool {
        // Clone the script for VM execution
        let script_copy = clone_array(self.script);

        // Create VM with initial stack from input data
        let mut vm = ScriptVMTrait::new_with_stack(script_copy, input_data);

        // Execute the script
        match vm.execute() {
            Result::Ok(()) => {
                // Check that exactly one element remains
                if vm.stack.len() != 1 {
                    return false;
                }

                // Check that the result is truthy
                let result = vm.stack.at(0);
                is_truthy(result)
            },
            Result::Err(_) => false,
        }
    }

    /// Verify with detailed error information
    fn verify_detailed(
        self: @Covenant, input_data: Array<ByteArray>
    ) -> Result<bool, VMError> {
        let script_copy = clone_array(self.script);
        let mut vm = ScriptVMTrait::new_with_stack(script_copy, input_data);

        vm.execute()?;

        if vm.stack.len() != 1 {
            return Result::Ok(false);
        }

        let result = vm.stack.at(0);
        Result::Ok(is_truthy(result))
    }
}

/// Clone an Array<u8>
fn clone_array(src: @Array<u8>) -> Array<u8> {
    let mut result: Array<u8> = ArrayTrait::new();
    let mut i: usize = 0;
    while i < src.len() {
        result.append(*src.at(i));
        i += 1;
    };
    result
}

/// Builder pattern for creating covenant scripts
#[derive(Drop)]
pub struct CovenantBuilder {
    script: Array<u8>,
}

#[generate_trait]
pub impl CovenantBuilderImpl of CovenantBuilderTrait {
    /// Create a new covenant builder
    fn new() -> CovenantBuilder {
        CovenantBuilder { script: ArrayTrait::new() }
    }

    /// Add push data using Bitcoin standard opcodes
    /// Uses direct push (0x01-0x4b) for data up to 75 bytes
    /// Uses PUSHDATA1 (0x4c) for data 76-255 bytes
    fn push_data(ref self: CovenantBuilder, data: ByteArray) -> () {
        let len: u32 = data.len();
        if len == 0 {
            // OP_0 / OP_FALSE for empty data
            self.script.append(0x00);
        } else if len <= 75 {
            // Direct push: opcode is the length itself (0x01-0x4b)
            self.script.append(len.try_into().unwrap());
            let mut i: usize = 0;
            while i < data.len() {
                self.script.append(data.at(i).unwrap());
                i += 1;
            };
        } else {
            // PUSHDATA1 for data 76-255 bytes
            self.script.append(0x4c);  // OP_PUSHDATA1
            self.script.append(len.try_into().unwrap());
            let mut i: usize = 0;
            while i < data.len() {
                self.script.append(data.at(i).unwrap());
                i += 1;
            };
        }
    }

    /// Add OP_CAT
    fn cat(ref self: CovenantBuilder) -> () {
        use crate::opcodes::OP_CAT;
        self.script.append(OP_CAT);
    }

    /// Add OP_ADD
    fn add(ref self: CovenantBuilder) -> () {
        use crate::opcodes::OP_ADD;
        self.script.append(OP_ADD);
    }

    /// Add OP_DUP
    fn dup(ref self: CovenantBuilder) -> () {
        use crate::opcodes::OP_DUP;
        self.script.append(OP_DUP);
    }

    /// Add OP_DROP
    fn drop(ref self: CovenantBuilder) -> () {
        use crate::opcodes::OP_DROP;
        self.script.append(OP_DROP);
    }

    /// Add OP_EQUAL
    fn equal(ref self: CovenantBuilder) -> () {
        use crate::opcodes::OP_EQUAL;
        self.script.append(OP_EQUAL);
    }

    /// Add OP_VERIFY
    fn verify(ref self: CovenantBuilder) -> () {
        use crate::opcodes::OP_VERIFY;
        self.script.append(OP_VERIFY);
    }

    /// Build the covenant
    fn build(self: CovenantBuilder) -> Covenant {
        Covenant { script: self.script }
    }
}
