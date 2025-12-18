#!/bin/bash
# CatoVerifier Deployment Script
#
# Prerequisites:
# 1. sncast installed (part of starknet-foundry)
# 2. Account configured in snfoundry.toml or via environment
# 3. Funded account on target network
#
# Usage:
#   ./scripts/deploy.sh [network] [integrity_verifier_address]
#
# Example:
#   ./scripts/deploy.sh sepolia 0x04e3d...

set -e

NETWORK="${1:-sepolia}"
INTEGRITY_VERIFIER="${2:-0x0}"  # Placeholder - update with actual address

# Herodotus Integrity Verifier addresses
# Sepolia: Check https://docs.herodotus.dev for latest addresses
# Mainnet: Check https://docs.herodotus.dev for latest addresses

echo "============================================"
echo "CatoVerifier Deployment"
echo "============================================"
echo ""
echo "Network: $NETWORK"
echo "Integrity Verifier: $INTEGRITY_VERIFIER"
echo ""

# Navigate to contracts directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Build the contract
echo "[1/4] Building contract..."
scarb build

# Get the contract class file
CONTRACT_CLASS="target/dev/cato_verifier_CatoVerifier.contract_class.json"

if [ ! -f "$CONTRACT_CLASS" ]; then
    echo "Error: Contract class file not found at $CONTRACT_CLASS"
    exit 1
fi

echo "[2/4] Declaring contract class..."
echo ""
echo "Run this command to declare the contract:"
echo ""
echo "  sncast --profile $NETWORK declare \\"
echo "    --contract-name CatoVerifier"
echo ""
echo "This will return a CLASS_HASH."
echo ""

read -p "Enter the CLASS_HASH from declaration (or 'skip' to use existing): " CLASS_HASH

if [ "$CLASS_HASH" = "skip" ]; then
    read -p "Enter existing CLASS_HASH: " CLASS_HASH
fi

echo ""
echo "[3/4] Deploying contract..."
echo ""

# Constructor arguments:
# 1. integrity_verifier: ContractAddress - The Herodotus Integrity Verifier address
# 2. cato_program_hash: felt252 - Hash identifying the Cato Bitcoin Script VM
# 3. owner: ContractAddress - Owner address for admin functions

# Get the program hash from our execution
CATO_PROGRAM_HASH="0xb889c6a27b4a5cb9"  # From our proof submission script

echo "Constructor arguments:"
echo "  - integrity_verifier: $INTEGRITY_VERIFIER"
echo "  - cato_program_hash: $CATO_PROGRAM_HASH"
echo "  - owner: (your deployer address)"
echo ""
echo "Run this command to deploy:"
echo ""
echo "  sncast --profile $NETWORK deploy \\"
echo "    --class-hash $CLASS_HASH \\"
echo "    --constructor-calldata $INTEGRITY_VERIFIER $CATO_PROGRAM_HASH <YOUR_ADDRESS>"
echo ""

read -p "Enter the deployed CONTRACT_ADDRESS: " CONTRACT_ADDRESS

echo ""
echo "[4/4] Deployment Complete!"
echo "============================================"
echo ""
echo "CatoVerifier deployed at: $CONTRACT_ADDRESS"
echo "Network: $NETWORK"
echo ""
echo "Next steps:"
echo "1. Verify source on Starkscan/Voyager"
echo "2. Generate STARK proof using Stone Prover"
echo "3. Submit proof to Herodotus Integrity"
echo "4. Call verify_bitcoin_script() with program/output hashes"
echo ""

# Save deployment info
DEPLOY_FILE="deployments/${NETWORK}.json"
mkdir -p deployments
cat > "$DEPLOY_FILE" << EOF
{
  "network": "$NETWORK",
  "contract_address": "$CONTRACT_ADDRESS",
  "class_hash": "$CLASS_HASH",
  "integrity_verifier": "$INTEGRITY_VERIFIER",
  "cato_program_hash": "$CATO_PROGRAM_HASH",
  "deployed_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

echo "Deployment info saved to: $DEPLOY_FILE"
