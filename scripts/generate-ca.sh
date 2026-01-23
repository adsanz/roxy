#!/usr/bin/env bash
#
# Generate CA certificate and key for Roxy MITM proxy
#
# Usage: ./scripts/generate-ca.sh [output_dir]
#
# Outputs:
#   ca.key - CA private key (keep secure!)
#   ca.crt - CA certificate (add to client trust stores)
#

set -euo pipefail

OUTPUT_DIR="${1:-.}"
CA_DAYS="${CA_DAYS:-3650}"  # 10 years default
CA_KEY_SIZE="${CA_KEY_SIZE:-4096}"
CA_CN="${CA_CN:-Roxy Proxy CA}"
CA_ORG="${CA_ORG:-Roxy}"

mkdir -p "$OUTPUT_DIR"

echo "Generating CA private key..."
openssl genrsa -out "$OUTPUT_DIR/ca.key" "$CA_KEY_SIZE"

echo "Generating CA certificate..."
openssl req -new -x509 \
    -key "$OUTPUT_DIR/ca.key" \
    -out "$OUTPUT_DIR/ca.crt" \
    -days "$CA_DAYS" \
    -subj "/CN=$CA_CN/O=$CA_ORG" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo ""
echo "Generated CA files in $OUTPUT_DIR:"
echo "  ca.key - Private key (keep secure!)"
echo "  ca.crt - Certificate (add to trust stores)"
echo ""
echo "To add CA to system trust store:"
echo ""
echo "  Linux (Debian/Ubuntu):"
echo "    sudo cp $OUTPUT_DIR/ca.crt /usr/local/share/ca-certificates/roxy-ca.crt"
echo "    sudo update-ca-certificates"
echo ""
echo "  Linux (RHEL/CentOS/Fedora):"
echo "    sudo cp $OUTPUT_DIR/ca.crt /etc/pki/ca-trust/source/anchors/roxy-ca.crt"
echo "    sudo update-ca-trust"
echo ""
echo "  macOS:"
echo "    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $OUTPUT_DIR/ca.crt"
echo ""
echo "  Windows (PowerShell as Admin):"
echo "    Import-Certificate -FilePath $OUTPUT_DIR\\ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root"
