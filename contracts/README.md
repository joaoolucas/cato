# CatoVerifier Contract

On-chain STARK proof verifier for Bitcoin Script execution on Starknet.

## Architecture

```
Cato VM (off-chain) --> Stwo Prover --> CatoVerifier <-- Herodotus FactRegistry
```

## Deployment (Sepolia)

| Field | Value |
|-------|-------|
| Contract | [`0x02c22b...71fe`](https://sepolia.starkscan.co/contract/0x02c22b1c1c09bf150f43d3207854f016677cf26cf560d9b34a3e6b019b3571fe) |
| FactRegistry | [`0x4ce785...b8c`](https://sepolia.starkscan.co/contract/0x4ce7851f00b6c3289674841fd7a1b96b6fd41ed1edc248faccd672c26371b8c) |

## Interface

```cairo
#[starknet::interface]
trait ICatoVerifier {
    fn verify_bitcoin_script(
        ref self,
        program_hash: felt252,
        output_hash: felt252,
    ) -> bool;
}
```

## Build & Deploy

```bash
cd contracts
scarb build

# Declare and deploy
sncast --profile sepolia declare --contract-name CatoVerifier
sncast --profile sepolia deploy \
  --class-hash <CLASS_HASH> \
  --constructor-calldata <FACT_REGISTRY> <CATO_PROGRAM_HASH> <OWNER>
```
