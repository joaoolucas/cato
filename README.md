# Cato

**A STARK-provable Bitcoin Script VM with OP_CAT support.**

Cato executes Bitcoin Script in Cairo and generates STARK proofs verifiable on Starknet. This enables trustless Bitcoin covenants and cross-chain state verification.

## Features

- **Bitcoin Script VM** - 80+ opcodes including arithmetic, crypto, stack, and flow control
- **OP_CAT** - Native concatenation opcode for covenant patterns
- **Circle STARKs** - Proof generation in ~7 seconds via Stwo
- **On-Chain Verification** - Proofs verifiable on Starknet

## Quick Start

```bash
# Build
scarb build

# Run tests (127 tests)
scarb test

# Execute and generate proof
scarb execute --print-program-output
/tmp/stwo-cairo/cairo-prove/target/release/cairo-prove prove \
    target/dev/cato.executable.json \
    proofs/cato_proof.json

# Verify locally
/tmp/stwo-cairo/cairo-prove/target/release/cairo-prove verify proofs/cato_proof.json
```

## Architecture

```
┌──────────────────┐    ┌─────────────────┐    ┌───────────────────┐
│  Bitcoin Script  │───▶│    Cato VM      │───▶│   Stwo Prover     │
│  (OP_CAT)        │    │    (Cairo)      │    │   (~7 seconds)    │
└──────────────────┘    └─────────────────┘    └─────────┬─────────┘
                                                         │
                                                         ▼
                        ┌─────────────────┐    ┌───────────────────┐
                        │  CatoVerifier   │◀───│   FactRegistry    │
                        │  (Starknet)     │    │   (Herodotus)     │
                        └─────────────────┘    └───────────────────┘
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

## Contract Deployment

| Network | Contract |
|---------|----------|
| Mainnet | [`0x016033...3617`](https://starkscan.co/contract/0x0160338e1ceb5a1e9e430484460a6b4bccaaa3a4b896a7f09980301a88603617) |
| Sepolia | [`0x02c22b...71fe`](https://sepolia.starkscan.co/contract/0x02c22b1c1c09bf150f43d3207854f016677cf26cf560d9b34a3e6b019b3571fe) |

## Project Structure

```
cato/
├── src/
│   ├── lib.cairo       # Entry point with provable execution demo
│   ├── vm.cairo        # Bitcoin Script VM
│   ├── opcodes.cairo   # Opcode definitions
│   ├── vault.cairo     # CatoVault recursive covenant
│   └── tests.cairo     # Test suite (127 tests)
├── contracts/
│   └── src/verifier.cairo  # On-chain verifier
└── proofs/             # Generated STARK proofs
```

## Building Stwo Prover

```bash
git clone https://github.com/starkware-libs/stwo-cairo.git /tmp/stwo-cairo
cd /tmp/stwo-cairo/cairo-prove && ./build.sh
```

## Performance

| Metric | Value |
|--------|-------|
| Proof Generation | ~7 seconds |
| Proof Size | ~17 MB |
| Max Stack Size | 1000 elements |
| Max Element Size | 520 bytes |

## References

- [BIP-347: OP_CAT](https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki)
- [Stwo Prover](https://github.com/starkware-libs/stwo)
- [Circle STARKs](https://eprint.iacr.org/2024/278)

## License

MIT
