#!/bin/bash
################################################################################
# Fetch AD Root CA Certificate
# Retrieves the Root CA certificate from Active Directory for LDAPS
################################################################################

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ ERROR: $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  WARNING: $1${NC}"; }
print_info() { echo -e "${CYAN}ℹ️  $1${NC}"; }

# Check if ldapsearch is available
if ! command -v ldapsearch &> /dev/null; then
    print_error "ldapsearch not found. Please install openldap-clients (RHEL/CentOS) or ldap-utils (Debian/Ubuntu)"
    exit 1
fi

# Check if openssl is available
if ! command -v openssl &> /dev/null; then
    print_error "openssl not found. Please install openssl"
    exit 1
fi

# Load environment variables from .env if available
if [ -f ".env" ]; then
    print_info "Loading LDAP configuration from .env"
    set -a
    source <(grep -E "^LDAP_" .env | sed 's/^/export /')
    set +a
fi

# Get LDAP connection details
LDAP_URL=${LDAP_URL:-"ldaps://dc.example.com:636"}
LDAP_BIND_DN=${LDAP_BIND_DN:-"CN=ldap-reader,OU=Service Accounts,DC=example,DC=com"}
LDAP_BIND_PASSWORD=${LDAP_BIND_PASSWORD:-""}

if [ -z "$LDAP_BIND_PASSWORD" ]; then
    print_error "LDAP_BIND_PASSWORD not set in .env"
    exit 1
fi

# Extract host and port
LDAP_HOST=$(echo "$LDAP_URL" | sed -E 's|ldaps?://([^:]+).*|\1|')
LDAP_PORT=$(echo "$LDAP_URL" | sed -E 's|ldaps?://[^:]+:?([0-9]+)?.*|\1|')
LDAP_PORT=${LDAP_PORT:-636}

# Determine protocol
if [[ "$LDAP_URL" =~ ^ldaps:// ]]; then
    LDAP_PROTOCOL="ldaps"
else
    LDAP_PROTOCOL="ldap"
fi

# Extract domain DN from bind DN (everything starting with DC=)
DOMAIN_DN=$(echo "$LDAP_BIND_DN" | sed 's/^[^D]*\(DC=.*\)$/\1/')

print_info "Fetching certificate from $LDAP_HOST:$LDAP_PORT"
print_info "Domain DN: $DOMAIN_DN"

# Create certs directory
mkdir -p ./certs

# Try to find the CA certificate in AD
CA_BASES=(
    "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,$DOMAIN_DN"
    "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,$DOMAIN_DN"
)

CERT_FETCHED=false

for CA_BASE in "${CA_BASES[@]}"; do
    print_info "Searching at: $CA_BASE"

    # Use LDAPTLS_REQCERT=never to bypass cert verification during fetch
    # Use -LLL for LDIF output without comments, -o ldif-wrap=no for no line wrapping
    CERT_DATA=$(LDAPTLS_REQCERT=never ldapsearch -x -LLL -o ldif-wrap=no \
        -H "${LDAP_PROTOCOL}://${LDAP_HOST}:${LDAP_PORT}" \
        -D "$LDAP_BIND_DN" \
        -w "$LDAP_BIND_PASSWORD" \
        -b "$CA_BASE" \
        -s sub \
        "(objectClass=*)" \
        cACertificate \
        2>/dev/null | \
        grep "^cACertificate::" | \
        head -1 | \
        sed 's/^cACertificate:: //')

    if [ -n "$CERT_DATA" ]; then
        print_success "Found certificate at: $CA_BASE"

        # Decode and convert to PEM
        echo "$CERT_DATA" | base64 -d | \
            openssl x509 -inform DER -outform PEM > ./certs/ad-root-ca.crt 2>/dev/null

        if [ -f "./certs/ad-root-ca.crt" ] && [ -s "./certs/ad-root-ca.crt" ]; then
            # Verify it's a valid certificate
            CERT_SUBJECT=$(openssl x509 -in ./certs/ad-root-ca.crt -noout -subject 2>/dev/null | sed 's/subject=//')
            CERT_ISSUER=$(openssl x509 -in ./certs/ad-root-ca.crt -noout -issuer 2>/dev/null | sed 's/issuer=//')
            CERT_EXPIRY=$(openssl x509 -in ./certs/ad-root-ca.crt -noout -enddate 2>/dev/null | sed 's/notAfter=//')

            print_success "Certificate retrieved and saved successfully!"
            echo ""
            echo "Certificate Details:"
            echo "  Subject: $CERT_SUBJECT"
            echo "  Issuer:  $CERT_ISSUER"
            echo "  Expires: $CERT_EXPIRY"
            echo ""
            echo "Certificate saved to: ./certs/ad-root-ca.crt"

            chmod 644 ./certs/ad-root-ca.crt
            CERT_FETCHED=true
            break
        fi
    fi
done

if [ "$CERT_FETCHED" = false ]; then
    print_error "Could not automatically fetch the certificate"
    echo ""
    echo "Possible reasons:"
    echo "  • Your AD doesn't store certs in standard locations"
    echo "  • LDAP bind credentials don't have read access to PKI containers"
    echo "  • Certificate container is in a non-standard location"
    echo ""
    print_info "You can manually export the Root CA certificate from your AD server:"
    echo "  1. On your AD server, run: certutil -ca.cert ad-root-ca.cer"
    echo "  2. Convert to PEM: openssl x509 -inform DER -in ad-root-ca.cer -out ad-root-ca.crt"
    echo "  3. Copy to ./certs/ad-root-ca.crt"
    exit 1
fi

exit 0
