#!/usr/bin/env python3
"""
Generate Bitcoin Script test vectors with OP_CAT enabled.

This script implements a Bitcoin Script interpreter with OP_CAT re-enabled
to generate ground-truth test vectors that Cato must match exactly.

OP_CAT was disabled in Bitcoin in 2010 but its behavior is well-defined:
- Pop two elements: top=b, second=a
- Concatenate: result = a || b (a first, then b)
- Push result back
- Fail if result > 520 bytes (MAX_SCRIPT_ELEMENT_SIZE)

Reference: https://en.bitcoin.it/wiki/Script
"""

import json
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union
from enum import IntEnum

# Bitcoin Script constants
MAX_SCRIPT_ELEMENT_SIZE = 520
MAX_STACK_SIZE = 1000

# Opcodes we support
class OP(IntEnum):
    OP_0 = 0x00  # We use this as OP_PUSH in Cato
    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    OP_PUSHDATA4 = 0x4e
    OP_1NEGATE = 0x4f
    OP_1 = 0x51
    OP_16 = 0x60
    OP_NOP = 0x61
    OP_VERIFY = 0x69
    OP_RETURN = 0x6a
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_CAT = 0x7e  # Disabled in Bitcoin, we re-enable it
    OP_EQUAL = 0x87
    OP_ADD = 0x93

class ScriptError(Exception):
    """Bitcoin Script execution error"""
    pass

def decode_script_num(data: bytes) -> int:
    """
    Decode Bitcoin script number (little-endian signed magnitude).

    Bitcoin uses a unique encoding:
    - Little-endian byte order
    - Sign bit is the MSB of the last byte
    - Empty array = 0
    """
    if len(data) == 0:
        return 0

    # Check if negative (MSB of last byte)
    negative = (data[-1] & 0x80) != 0

    # Build the absolute value
    result = 0
    for i, byte in enumerate(data):
        if i == len(data) - 1 and negative:
            # Remove sign bit from last byte
            result |= (byte & 0x7f) << (8 * i)
        else:
            result |= byte << (8 * i)

    return -result if negative else result

def encode_script_num(value: int) -> bytes:
    """
    Encode integer as Bitcoin script number (little-endian signed magnitude).
    """
    if value == 0:
        return b''

    negative = value < 0
    absvalue = abs(value)

    result = []
    while absvalue > 0:
        result.append(absvalue & 0xff)
        absvalue >>= 8

    # Add sign bit
    if result[-1] & 0x80:
        # Need an extra byte for sign
        result.append(0x80 if negative else 0x00)
    elif negative:
        # Set sign bit in existing last byte
        result[-1] |= 0x80

    return bytes(result)

def is_truthy(data: bytes) -> bool:
    """
    Check if stack element is truthy (Bitcoin semantics).

    Falsy values:
    - Empty array
    - All zeros (including negative zero: 0x80, 0x0080, etc.)
    """
    if len(data) == 0:
        return False

    # Check for all zeros (with possible negative zero)
    for i, byte in enumerate(data):
        if i == len(data) - 1:
            # Last byte: check ignoring sign bit
            if byte & 0x7f != 0:
                return True
        else:
            if byte != 0:
                return True

    return False

class BitcoinScriptVM:
    """
    Minimal Bitcoin Script interpreter with OP_CAT enabled.
    """

    def __init__(self):
        self.stack: List[bytes] = []
        self.error: Optional[str] = None

    def execute(self, script: bytes, initial_stack: List[bytes] = None) -> bool:
        """Execute a script and return True if successful."""
        self.stack = list(initial_stack) if initial_stack else []
        self.error = None

        pc = 0
        while pc < len(script):
            opcode = script[pc]
            pc += 1

            try:
                # Handle push operations (opcodes 0x01-0x4b push that many bytes)
                if 0x01 <= opcode <= 0x4b:
                    if pc + opcode > len(script):
                        raise ScriptError("PUSH: not enough data")
                    self.stack.append(script[pc:pc+opcode])
                    pc += opcode
                    continue

                # OP_0 / OP_FALSE (in Cato we use this as OP_PUSH with length byte)
                if opcode == OP.OP_0:
                    # In our Cato format: OP_PUSH length data
                    if pc >= len(script):
                        raise ScriptError("OP_PUSH: missing length")
                    length = script[pc]
                    pc += 1
                    if pc + length > len(script):
                        raise ScriptError("OP_PUSH: not enough data")
                    data = script[pc:pc+length]
                    if len(data) > MAX_SCRIPT_ELEMENT_SIZE:
                        raise ScriptError("OP_PUSH: element too large")
                    if len(self.stack) >= MAX_STACK_SIZE:
                        raise ScriptError("Stack overflow")
                    self.stack.append(data)
                    pc += length
                    continue

                if opcode == OP.OP_VERIFY:
                    if len(self.stack) < 1:
                        raise ScriptError("OP_VERIFY: stack underflow")
                    top = self.stack.pop()
                    if not is_truthy(top):
                        raise ScriptError("OP_VERIFY: failed")
                    continue

                if opcode == OP.OP_DROP:
                    if len(self.stack) < 1:
                        raise ScriptError("OP_DROP: stack underflow")
                    self.stack.pop()
                    continue

                if opcode == OP.OP_DUP:
                    if len(self.stack) < 1:
                        raise ScriptError("OP_DUP: stack underflow")
                    if len(self.stack) >= MAX_STACK_SIZE:
                        raise ScriptError("Stack overflow")
                    self.stack.append(self.stack[-1])
                    continue

                if opcode == OP.OP_CAT:
                    # OP_CAT: Pop b, pop a, push a||b
                    if len(self.stack) < 2:
                        raise ScriptError("OP_CAT: stack underflow")
                    b = self.stack.pop()
                    a = self.stack.pop()
                    result = a + b  # Concatenate a first, then b
                    if len(result) > MAX_SCRIPT_ELEMENT_SIZE:
                        raise ScriptError("OP_CAT: result too large")
                    if len(self.stack) >= MAX_STACK_SIZE:
                        raise ScriptError("Stack overflow")
                    self.stack.append(result)
                    continue

                if opcode == OP.OP_EQUAL:
                    if len(self.stack) < 2:
                        raise ScriptError("OP_EQUAL: stack underflow")
                    b = self.stack.pop()
                    a = self.stack.pop()
                    result = encode_script_num(1 if a == b else 0)
                    self.stack.append(result)
                    continue

                if opcode == OP.OP_ADD:
                    if len(self.stack) < 2:
                        raise ScriptError("OP_ADD: stack underflow")
                    b = decode_script_num(self.stack.pop())
                    a = decode_script_num(self.stack.pop())
                    result = encode_script_num(a + b)
                    if len(result) > MAX_SCRIPT_ELEMENT_SIZE:
                        raise ScriptError("OP_ADD: result too large")
                    self.stack.append(result)
                    continue

                raise ScriptError(f"Unknown opcode: 0x{opcode:02x}")

            except ScriptError as e:
                self.error = str(e)
                return False

        return True

def generate_test_vector(name: str, description: str,
                         initial_stack: List[bytes], script: bytes,
                         vm: BitcoinScriptVM) -> dict:
    """Generate a single test vector by running through the Bitcoin VM."""

    success = vm.execute(script, initial_stack)

    vector = {
        "name": name,
        "description": description,
        "initial_stack": [s.hex() for s in initial_stack],
        "script": script.hex(),
    }

    if success:
        vector["expected_final_stack"] = [s.hex() for s in vm.stack]
    else:
        vector["expected_error"] = vm.error

    return vector

def main():
    vm = BitcoinScriptVM()
    vectors = []

    # ============================================
    # OP_CAT Test Vectors
    # ============================================

    # Basic concatenation
    vectors.append(generate_test_vector(
        "cat_hello_world",
        "Concatenate 'hello' and 'world'",
        [b"hello", b"world"],
        bytes([OP.OP_CAT]),
        vm
    ))

    # Empty strings
    vectors.append(generate_test_vector(
        "cat_empty_left",
        "Empty string + 'abc'",
        [b"", b"abc"],
        bytes([OP.OP_CAT]),
        vm
    ))

    vectors.append(generate_test_vector(
        "cat_empty_right",
        "'abc' + empty string",
        [b"abc", b""],
        bytes([OP.OP_CAT]),
        vm
    ))

    vectors.append(generate_test_vector(
        "cat_both_empty",
        "Two empty strings",
        [b"", b""],
        bytes([OP.OP_CAT]),
        vm
    ))

    # Binary data with null bytes
    vectors.append(generate_test_vector(
        "cat_binary_with_nulls",
        "Binary data with null bytes",
        [bytes([0x00, 0xff, 0x00]), bytes([0xff, 0x00, 0xff])],
        bytes([OP.OP_CAT]),
        vm
    ))

    # Single bytes
    vectors.append(generate_test_vector(
        "cat_single_bytes",
        "Concatenate single bytes",
        [bytes([0x01]), bytes([0x02])],
        bytes([OP.OP_CAT]),
        vm
    ))

    # All byte values (verify no transformation)
    all_bytes_a = bytes(range(0, 128))
    all_bytes_b = bytes(range(128, 256))
    vectors.append(generate_test_vector(
        "cat_all_byte_values",
        "All 256 byte values preserved",
        [all_bytes_a, all_bytes_b],
        bytes([OP.OP_CAT]),
        vm
    ))

    # Maximum size (260 + 260 = 520)
    max_a = bytes([i % 256 for i in range(260)])
    max_b = bytes([(i + 128) % 256 for i in range(260)])
    vectors.append(generate_test_vector(
        "cat_max_size_520",
        "Maximum valid size 260+260=520",
        [max_a, max_b],
        bytes([OP.OP_CAT]),
        vm
    ))

    # Exceeds max size (261 + 261 = 522)
    over_a = bytes([i % 256 for i in range(261)])
    over_b = bytes([i % 256 for i in range(261)])
    vectors.append(generate_test_vector(
        "cat_exceeds_max_size",
        "Exceeds max: 261+261=522",
        [over_a, over_b],
        bytes([OP.OP_CAT]),
        vm
    ))

    # Stack underflow - empty stack
    vectors.append(generate_test_vector(
        "cat_underflow_empty",
        "OP_CAT with empty stack",
        [],
        bytes([OP.OP_CAT]),
        vm
    ))

    # Stack underflow - one element
    vectors.append(generate_test_vector(
        "cat_underflow_one",
        "OP_CAT with only one element",
        [bytes([0xde, 0xad, 0xbe, 0xef])],
        bytes([OP.OP_CAT]),
        vm
    ))

    # Chained CAT operations
    vectors.append(generate_test_vector(
        "cat_chain_4_elements",
        "Chain: [a,b,c,d] with 3 CATs",
        [b"a", b"b", b"c", b"d"],
        bytes([OP.OP_CAT, OP.OP_CAT, OP.OP_CAT]),
        vm
    ))

    # DUP then CAT
    vectors.append(generate_test_vector(
        "cat_with_dup",
        "DUP then CAT doubles string",
        [b"ABC"],
        bytes([OP.OP_DUP, OP.OP_CAT]),
        vm
    ))

    # ============================================
    # OP_ADD Test Vectors
    # ============================================

    vectors.append(generate_test_vector(
        "add_2_plus_3",
        "2 + 3 = 5",
        [encode_script_num(2), encode_script_num(3)],
        bytes([OP.OP_ADD]),
        vm
    ))

    vectors.append(generate_test_vector(
        "add_zero_left",
        "0 + 42 = 42",
        [encode_script_num(0), encode_script_num(42)],
        bytes([OP.OP_ADD]),
        vm
    ))

    vectors.append(generate_test_vector(
        "add_negative",
        "-5 + 10 = 5",
        [encode_script_num(-5), encode_script_num(10)],
        bytes([OP.OP_ADD]),
        vm
    ))

    vectors.append(generate_test_vector(
        "add_two_negatives",
        "-3 + -7 = -10",
        [encode_script_num(-3), encode_script_num(-7)],
        bytes([OP.OP_ADD]),
        vm
    ))

    vectors.append(generate_test_vector(
        "add_cancel_to_zero",
        "5 + -5 = 0",
        [encode_script_num(5), encode_script_num(-5)],
        bytes([OP.OP_ADD]),
        vm
    ))

    vectors.append(generate_test_vector(
        "add_127_plus_1",
        "127 + 1 = 128 (needs 2 bytes)",
        [encode_script_num(127), encode_script_num(1)],
        bytes([OP.OP_ADD]),
        vm
    ))

    vectors.append(generate_test_vector(
        "add_256_plus_256",
        "256 + 256 = 512",
        [encode_script_num(256), encode_script_num(256)],
        bytes([OP.OP_ADD]),
        vm
    ))

    # ============================================
    # Combined Script Vectors
    # ============================================

    # PUSH + CAT
    script_push_cat = bytes([
        OP.OP_0, 2, ord('A'), ord('B'),  # PUSH "AB"
        OP.OP_0, 2, ord('C'), ord('D'),  # PUSH "CD"
        OP.OP_CAT
    ])
    vectors.append(generate_test_vector(
        "script_push_cat",
        "PUSH 'AB' PUSH 'CD' CAT",
        [],
        script_push_cat,
        vm
    ))

    # CAT + VERIFY (truthy result)
    vectors.append(generate_test_vector(
        "cat_verify_truthy",
        "CAT produces truthy, VERIFY passes",
        [bytes([0x01]), bytes([0x02])],
        bytes([OP.OP_CAT, OP.OP_VERIFY]),
        vm
    ))

    # CAT + VERIFY (falsy result - both empty)
    vectors.append(generate_test_vector(
        "cat_verify_falsy",
        "CAT of empties is falsy, VERIFY fails",
        [b"", b""],
        bytes([OP.OP_CAT, OP.OP_VERIFY]),
        vm
    ))

    # Save vectors
    output = {
        "description": "Bitcoin Script ground-truth test vectors with OP_CAT enabled",
        "generated_by": "Bitcoin-compatible interpreter (generate_bitcoin_vectors.py)",
        "constants": {
            "MAX_SCRIPT_ELEMENT_SIZE": MAX_SCRIPT_ELEMENT_SIZE,
            "MAX_STACK_SIZE": MAX_STACK_SIZE
        },
        "opcodes": {
            "OP_PUSH": "0x00 (followed by length byte and data)",
            "OP_CAT": "0x7e",
            "OP_ADD": "0x93",
            "OP_DUP": "0x76",
            "OP_DROP": "0x75",
            "OP_EQUAL": "0x87",
            "OP_VERIFY": "0x69"
        },
        "test_vectors": vectors
    }

    output_path = "test_vectors/bitcoin_ground_truth.json"
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"Generated {len(vectors)} test vectors to {output_path}")

    # Print summary
    passed = sum(1 for v in vectors if "expected_final_stack" in v)
    failed = sum(1 for v in vectors if "expected_error" in v)
    print(f"  Success cases: {passed}")
    print(f"  Error cases: {failed}")

    # Print a few examples
    print("\nExample vectors:")
    for v in vectors[:3]:
        print(f"\n  {v['name']}:")
        print(f"    initial_stack: {v['initial_stack']}")
        print(f"    script: {v['script']}")
        if "expected_final_stack" in v:
            print(f"    expected_final_stack: {v['expected_final_stack']}")
        else:
            print(f"    expected_error: {v['expected_error']}")

if __name__ == "__main__":
    main()
