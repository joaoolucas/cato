# Cato 🐱

**A STARK-provable Bitcoin Script VM with OP_CAT support.**

Cato executes Bitcoin Script in Cairo and generates cryptographic proofs using Circle STARKs. This enables verifiable Bitcoin covenant execution and OP_CAT research.

## Features

- **Bitcoin Script VM** - 80+ opcodes including arithmetic, crypto, stack, and flow control
- **OP_CAT** - Native concatenation opcode for covenant patterns
- **Circle STARKs** - Proof generation in ~8 seconds via Stwo
- **Verifiable Execution** - Anyone can verify proofs cryptographically

## Quick Start

```bash
# Build
scarb build

# Run tests (20 tests)
scarb cairo-test

# Execute Bitcoin Script
scarb execute --print-program-output
```

## Generate & Verify Proof

```bash
# Build Stwo prover (first time only)
git clone https://github.com/starkware-libs/stwo-cairo.git /tmp/stwo-cairo
cd /tmp/stwo-cairo/cairo-prove && ./build.sh

# Generate STARK proof
/tmp/stwo-cairo/cairo-prove/target/release/cairo-prove prove \
    target/dev/cato.executable.json \
    proofs/cato_proof.json

# Verify proof
/tmp/stwo-cairo/cairo-prove/target/release/cairo-prove verify proofs/cato_proof.json
```

## Architecture

```
┌──────────────────┐    ┌─────────────────┐    ┌───────────────────┐
│  Bitcoin Script  │───▶│    Cato VM      │───▶│   Stwo Prover     │
│  (OP_CAT)        │    │    (Cairo)      │    │   (~8 seconds)    │
└──────────────────┘    └─────────────────┘    └─────────┬─────────┘
                                                         │
                                                         ▼
                                               ┌───────────────────┐
                                               │   STARK Proof     │
                                               │   (verifiable)    │
                                               └───────────────────┘
```

## Supported Opcodes

| Category | Opcodes |
|----------|---------|
| Constants | `OP_0` `OP_1`-`OP_16` `OP_PUSHDATA1` |
| Stack | `OP_DUP` `OP_DROP` `OP_SWAP` `OP_ROT` `OP_OVER` `OP_PICK` `OP_ROLL` `OP_TOALTSTACK` `OP_FROMALTSTACK` |
| Splice | `OP_CAT` `OP_SIZE` |
| Arithmetic | `OP_ADD` |
| Logic | `OP_EQUAL` `OP_EQUALVERIFY` `OP_VERIFY` |
| Crypto | `OP_SHA256` `OP_CHECKSIG` `OP_CHECKSIGVERIFY` `OP_CHECKSIGADD` |
| Timelock | `OP_CHECKLOCKTIMEVERIFY` `OP_CHECKSEQUENCEVERIFY` |

## Project Structure

```
cato/
├── src/
│   ├── lib.cairo       # Entry point with provable execution
│   ├── vm.cairo        # Bitcoin Script VM
│   ├── opcodes.cairo   # Opcode definitions
│   └── tests.cairo     # Test suite (20 tests)
└── proofs/             # Generated STARK proofs
```

## Performance

| Metric | Value |
|--------|-------|
| Proof Generation | ~8 seconds |
| Proof Size | ~17 MB |
| Max Stack Size | 1000 elements |
| Max Element Size | 520 bytes |

## References

- [BIP-347: OP_CAT](https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki)
- [Stwo Prover](https://github.com/starkware-libs/stwo)
- [Circle STARKs](https://eprint.iacr.org/2024/278)

## License

MIT
