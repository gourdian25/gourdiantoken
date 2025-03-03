#!/bin/bash

# Script to generate RSA keys for JWT token signing
# Used with gourdiantoken package

# Set the output directory
OUTPUT_DIR="keys"

# Ensure the directory exists
mkdir -p "${OUTPUT_DIR}"

# Define output file paths with precise naming
JWT_PRIVATE_KEY="${OUTPUT_DIR}/rsa_private.pem"
JWT_PUBLIC_KEY="${OUTPUT_DIR}/rsa_public.pem"  # Changed variable name to match later usage

echo "Generating RSA keys for JWT token signing..."

# Generate RSA private key (2048 bits)
openssl genpkey -algorithm RSA -out "${JWT_PRIVATE_KEY}" -pkeyopt rsa_keygen_bits:2048

# Extract public key from the private key
openssl rsa -in "${JWT_PRIVATE_KEY}" -pubout -out "${JWT_PUBLIC_KEY}"

# Set appropriate permissions
chmod 600 "${JWT_PRIVATE_KEY}"  # Restrictive permissions for private key
chmod 644 "${JWT_PUBLIC_KEY}"   # Public key can be readable

echo "JWT RSA key generation completed successfully:"
echo "  - Private Key: ${JWT_PRIVATE_KEY}"
echo "  - Public Key: ${JWT_PUBLIC_KEY}"
echo ""
echo "Use these paths in your gourdiantoken configuration:"
echo "  PrivateKeyPath: \"${JWT_PRIVATE_KEY}\","
echo "  PublicKeyPath: \"${JWT_PUBLIC_KEY}\","