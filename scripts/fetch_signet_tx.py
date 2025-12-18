#!/usr/bin/env python3
"""
Fetch Bitcoin Signet Transaction for Cato Verification

This script fetches a real transaction from Bitcoin Signet (or Bitcoin Inquisition
for OP_CAT transactions), extracts the witness data, computes the sighash,
and outputs the data in a format that Cato can verify.

Usage:
    python fetch_signet_tx.py <txid> [--input <n>]
    python fetch_signet_tx.py --demo  # Use a demo transaction

The output can be used to verify Bitcoin state transitions on Starknet.
"""

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple
import urllib.request
import urllib.error

# Bitcoin Signet block explorer API
SIGNET_API = "https://mempool.space/signet/api"

# Bitcoin Inquisition (Signet with OP_CAT) - alternative
INQUISITION_API = "https://mempool.space/signet/api"  # Same API, different node


@dataclass
class TxInput:
    txid: bytes  # 32 bytes, internal byte order
    vout: int
    script_sig: bytes
    sequence: int
    witness: List[bytes]


@dataclass
class TxOutput:
    value: int  # satoshis
    script_pubkey: bytes


@dataclass
class Transaction:
    version: int
    inputs: List[TxInput]
    outputs: List[TxOutput]
    locktime: int
    txid: str

    def serialize_for_sighash(self, input_index: int, script_code: bytes,
                               value: int, sighash_type: int = 1) -> bytes:
        """
        Serialize transaction for BIP143 sighash computation (SegWit).

        This is the preimage that gets double-SHA256'd for the sighash.
        """
        # BIP143 sighash preimage components
        preimage = b''

        # 1. nVersion (4 bytes, little-endian)
        preimage += struct.pack('<I', self.version)

        # 2. hashPrevouts (32 bytes) - SHA256(SHA256(all input outpoints))
        prevouts = b''
        for inp in self.inputs:
            prevouts += inp.txid[::-1]  # txid in internal byte order
            prevouts += struct.pack('<I', inp.vout)
        hash_prevouts = hashlib.sha256(hashlib.sha256(prevouts).digest()).digest()
        preimage += hash_prevouts

        # 3. hashSequence (32 bytes) - SHA256(SHA256(all input sequences))
        sequences = b''
        for inp in self.inputs:
            sequences += struct.pack('<I', inp.sequence)
        hash_sequence = hashlib.sha256(hashlib.sha256(sequences).digest()).digest()
        preimage += hash_sequence

        # 4. outpoint (36 bytes) - txid + vout for this input
        inp = self.inputs[input_index]
        preimage += inp.txid[::-1]
        preimage += struct.pack('<I', inp.vout)

        # 5. scriptCode (var_int length + script)
        preimage += self._var_int(len(script_code))
        preimage += script_code

        # 6. value (8 bytes, little-endian) - amount being spent
        preimage += struct.pack('<Q', value)

        # 7. nSequence (4 bytes) - sequence of this input
        preimage += struct.pack('<I', inp.sequence)

        # 8. hashOutputs (32 bytes) - SHA256(SHA256(all outputs))
        outputs = b''
        for out in self.outputs:
            outputs += struct.pack('<Q', out.value)
            outputs += self._var_int(len(out.script_pubkey))
            outputs += out.script_pubkey
        hash_outputs = hashlib.sha256(hashlib.sha256(outputs).digest()).digest()
        preimage += hash_outputs

        # 9. nLocktime (4 bytes)
        preimage += struct.pack('<I', self.locktime)

        # 10. sighash type (4 bytes)
        preimage += struct.pack('<I', sighash_type)

        return preimage

    def compute_sighash(self, input_index: int, script_code: bytes,
                        value: int, sighash_type: int = 1) -> bytes:
        """Compute the BIP143 sighash for a SegWit input."""
        preimage = self.serialize_for_sighash(input_index, script_code, value, sighash_type)
        return hashlib.sha256(hashlib.sha256(preimage).digest()).digest()

    @staticmethod
    def _var_int(n: int) -> bytes:
        if n < 0xfd:
            return bytes([n])
        elif n <= 0xffff:
            return b'\xfd' + struct.pack('<H', n)
        elif n <= 0xffffffff:
            return b'\xfe' + struct.pack('<I', n)
        else:
            return b'\xff' + struct.pack('<Q', n)


def fetch_transaction(txid: str, api_base: str = SIGNET_API) -> Optional[dict]:
    """Fetch transaction data from mempool.space API."""
    url = f"{api_base}/tx/{txid}"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        print(f"Error fetching transaction: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return None


def fetch_transaction_hex(txid: str, api_base: str = SIGNET_API) -> Optional[str]:
    """Fetch raw transaction hex."""
    url = f"{api_base}/tx/{txid}/hex"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return response.read().decode().strip()
    except Exception as e:
        print(f"Error fetching tx hex: {e}", file=sys.stderr)
        return None


def fetch_prev_output(txid: str, vout: int, api_base: str = SIGNET_API) -> Optional[dict]:
    """Fetch the previous output being spent."""
    url = f"{api_base}/tx/{txid}"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            tx_data = json.loads(response.read().decode())
            if vout < len(tx_data.get('vout', [])):
                return tx_data['vout'][vout]
    except Exception as e:
        print(f"Error fetching prev output: {e}", file=sys.stderr)
    return None


def parse_transaction(tx_data: dict, tx_hex: str = None) -> Transaction:
    """Parse transaction from API response."""
    inputs = []
    for vin in tx_data.get('vin', []):
        witness = []
        if 'witness' in vin:
            witness = [bytes.fromhex(w) for w in vin['witness']]

        inputs.append(TxInput(
            txid=bytes.fromhex(vin.get('txid', '0' * 64)),
            vout=vin.get('vout', 0),
            script_sig=bytes.fromhex(vin.get('scriptsig', '')),
            sequence=vin.get('sequence', 0xffffffff),
            witness=witness
        ))

    outputs = []
    for vout in tx_data.get('vout', []):
        outputs.append(TxOutput(
            value=vout.get('value', 0),
            script_pubkey=bytes.fromhex(vout.get('scriptpubkey', ''))
        ))

    return Transaction(
        version=tx_data.get('version', 2),
        inputs=inputs,
        outputs=outputs,
        locktime=tx_data.get('locktime', 0),
        txid=tx_data.get('txid', '')
    )


def extract_script_code(script_pubkey: bytes, witness: List[bytes]) -> bytes:
    """
    Extract the script code for sighash computation.

    For P2WPKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    For P2WSH: The witness script (last witness element)
    """
    if len(script_pubkey) == 22 and script_pubkey[0] == 0x00 and script_pubkey[1] == 0x14:
        # P2WPKH: version 0, 20-byte program
        pubkey_hash = script_pubkey[2:22]
        return bytes([
            0x76,  # OP_DUP
            0xa9,  # OP_HASH160
            0x14   # Push 20 bytes
        ]) + pubkey_hash + bytes([
            0x88,  # OP_EQUALVERIFY
            0xac   # OP_CHECKSIG
        ])

    elif len(script_pubkey) == 34 and script_pubkey[0] == 0x00 and script_pubkey[1] == 0x20:
        # P2WSH: version 0, 32-byte program (script hash)
        # Script code is the witness script (last element)
        if witness:
            return witness[-1]

    # Default: return the script pubkey itself
    return script_pubkey


def generate_cato_test_data(tx: Transaction, input_index: int,
                            prev_value: int, prev_script_pubkey: bytes) -> dict:
    """Generate test data for Cato verification."""
    inp = tx.inputs[input_index]

    # Extract script code for sighash
    script_code = extract_script_code(prev_script_pubkey, inp.witness)

    # Compute sighash
    sighash = tx.compute_sighash(input_index, script_code, prev_value)

    # Format witness stack for Cato
    witness_stack = [w.hex() for w in inp.witness]

    # Get the script to execute
    # For P2WSH, this is the witness script
    # For P2WPKH, this is the implied script
    exec_script = script_code.hex()

    return {
        "txid": tx.txid,
        "input_index": input_index,
        "prev_txid": inp.txid.hex(),
        "prev_vout": inp.vout,
        "prev_value_sats": prev_value,
        "prev_script_pubkey": prev_script_pubkey.hex(),
        "witness_stack": witness_stack,
        "script_code": exec_script,
        "sighash": sighash.hex(),
        "sighash_preimage": tx.serialize_for_sighash(input_index, script_code, prev_value).hex(),

        # Cato-specific format
        "cato_verification": {
            "description": "Data for Cato Bitcoin Script VM verification",
            "initial_stack": witness_stack[:-1] if len(witness_stack) > 1 else witness_stack,
            "script": exec_script,
            "expected_result": "truthy",
            "note": "Stack should end with truthy value if signature is valid"
        }
    }


def create_demo_transaction() -> dict:
    """
    Create a demo transaction that demonstrates OP_CAT verification.

    Since OP_CAT is only available on Bitcoin Inquisition (special Signet),
    we create a realistic test case that shows the verification workflow.
    """
    # This simulates a P2WSH transaction with an OP_CAT script
    # Script: <sig> <pubkey> <data_a> <data_b> | CAT EQUALVERIFY CHECKSIG

    demo_data = {
        "description": "Demo transaction for Cato OP_CAT verification",
        "note": "This demonstrates verifying a Bitcoin script with OP_CAT on Starknet",

        "transaction": {
            "txid": "demo_cat_tx_001",
            "version": 2,
            "locktime": 0
        },

        "input": {
            "index": 0,
            "prev_txid": "a" * 64,
            "prev_vout": 0,
            "prev_value_sats": 100000,  # 0.001 BTC

            # Witness script: <expected_concat> OP_EQUALVERIFY OP_1
            # Witness stack: [data_a, data_b, expected_concat]
            # Execution: CAT(data_a, data_b) EQUALVERIFY expected_concat -> leaves OP_1
            "witness_stack": [
                "48656c6c6f",  # "Hello"
                "576f726c64",  # "World"
                "48656c6c6f576f726c64",  # "HelloWorld" (expected)
            ],

            # Script: OP_CAT OP_EQUALVERIFY OP_1
            # Pops "World" and "Hello", concatenates to "HelloWorld"
            # Compares with expected, verifies equality
            # Pushes 1 (success)
            "script_hex": "7e886951",  # CAT EQUALVERIFY 1
        },

        "cato_verification": {
            "description": "Verify OP_CAT concatenation matches expected value",
            "initial_stack": [
                "48656c6c6f",  # "Hello" (bottom)
                "576f726c64",  # "World" (middle)
                "48656c6c6f576f726c64",  # "HelloWorld" (top)
            ],
            "script": "7e886951",  # CAT EQUALVERIFY OP_1
            "expected_final_stack": ["01"],
            "execution_trace": [
                "Initial: [Hello, World, HelloWorld]",
                "CAT: [Hello, WorldHelloWorld] - WRONG! CAT takes top two",
                "Actually: CAT pops World and HelloWorld, concats -> HelloWorldHelloWorld",
            ],
        }
    }

    # Fix the script to match proper stack behavior
    # Stack: [Hello, World, expected]
    # We want to CAT Hello+World and compare with expected
    #
    # Correct script:
    # OP_ROT (bring Hello to top): [World, expected, Hello]
    # OP_ROT (bring World to top): [expected, Hello, World]
    # OP_CAT: [expected, HelloWorld]
    # OP_EQUAL: [true/false]

    # Simpler approach with proper stack order:
    # Stack: [expected, Hello, World]
    # CAT: [expected, HelloWorld]
    # EQUAL: [1 or 0]

    demo_corrected = {
        "description": "Demo OP_CAT transaction for Cato verification",
        "note": "Verifies CAT(Hello, World) == HelloWorld on Starknet",

        "cato_verification": {
            "name": "cat_equality_check",
            "initial_stack": [
                "48656c6c6f576f726c64",  # "HelloWorld" (expected, bottom)
                "48656c6c6f",  # "Hello"
                "576f726c64",  # "World" (top)
            ],
            # Script: CAT EQUAL
            "script_bytes": [0x7e, 0x87],  # OP_CAT, OP_EQUAL
            "script_hex": "7e87",
            "expected_final_stack": ["01"],  # True
            "execution_trace": [
                "1. Initial stack: [HelloWorld, Hello, World]",
                "2. OP_CAT: Pop World, Pop Hello, Push HelloWorld",
                "   Stack: [HelloWorld, HelloWorld]",
                "3. OP_EQUAL: Pop both, compare, push result",
                "   Stack: [01] (true)",
            ]
        }
    }

    return demo_corrected


def main():
    parser = argparse.ArgumentParser(
        description="Fetch Bitcoin Signet transaction for Cato verification"
    )
    parser.add_argument("txid", nargs="?", help="Transaction ID to fetch")
    parser.add_argument("--input", "-i", type=int, default=0,
                        help="Input index to verify (default: 0)")
    parser.add_argument("--demo", action="store_true",
                        help="Generate demo transaction data")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--api", default=SIGNET_API,
                        help="API base URL")

    args = parser.parse_args()

    if args.demo:
        result = create_demo_transaction()
        output = json.dumps(result, indent=2)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Demo data written to {args.output}")
        else:
            print(output)
        return

    if not args.txid:
        parser.error("Transaction ID required (or use --demo)")

    print(f"Fetching transaction {args.txid}...", file=sys.stderr)

    # Fetch transaction
    tx_data = fetch_transaction(args.txid, args.api)
    if not tx_data:
        print("Failed to fetch transaction", file=sys.stderr)
        sys.exit(1)

    # Parse transaction
    tx = parse_transaction(tx_data)

    if args.input >= len(tx.inputs):
        print(f"Input index {args.input} out of range (tx has {len(tx.inputs)} inputs)",
              file=sys.stderr)
        sys.exit(1)

    # Fetch previous output to get value and script
    inp = tx.inputs[args.input]
    prev_out = fetch_prev_output(inp.txid.hex(), inp.vout, args.api)

    if not prev_out:
        print("Failed to fetch previous output", file=sys.stderr)
        sys.exit(1)

    prev_value = prev_out.get('value', 0)
    prev_script = bytes.fromhex(prev_out.get('scriptpubkey', ''))

    # Generate test data
    result = generate_cato_test_data(tx, args.input, prev_value, prev_script)

    output = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Data written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
