#!/bin/bash -ex

function read_config() {
VAR=${1}
FILE=${2}

cat <<- EOF | python
import re, sys
regex = re.compile("${VAR}\s*=\s*([^\s]+)")
found = False
with open("${FILE}") as file:
    for line in file:
        result = regex.search(line)
        if result is not None:
            found = True
            print(result.group(1))
            break

if not found:
    sys.exit(1)

EOF
}

function create_ca_dir() {
CA_DIR=${1}

if [[ ! -d ${CA_DIR} ]]; then
    mkdir -p ${CA_DIR}
fi
for DIR in private db certs; do
    if [[ ! -d ${CA_DIR}/${DIR} ]]; then
        mkdir -p ${CA_DIR}/${DIR}
    fi
done
if [[ ! -f ${CA_DIR}/db/index ]]; then
    touch ${CA_DIR}/db/index
fi

if [[ ! -f ${CA_DIR}/db/serial ]]; then
    echo 01 > ${CA_DIR}/db/serial
fi

}

function generate_root_ca() {

ROOT_CA_CONFIG_FILE=${1:-root-ca.conf}

if [[ ! -f ${ROOT_CA_CONFIG_FILE} ]]; then
echo "Cannot find Root CA Config File ${ROOT_CA_CONFIG_FILE}"
exit 1
fi

ROOT_CA_NAME=$(read_config name ${ROOT_CA_CONFIG_FILE})
ROOT_CA_DOMAIN_SUFFIX=$(read_config domain_suffix ${ROOT_CA_CONFIG_FILE})
ROOT_CA_FULL_DOMAIN=${ROOT_CA_NAME}.${ROOT_CA_DOMAIN_SUFFIX}

ROOT_CA_DIR=$(pwd)/${ROOT_CA_FULL_DOMAIN}

ROOT_CA_CSR=${ROOT_CA_DIR}/${ROOT_CA_FULL_DOMAIN}.csr
ROOT_CA_CRT=${ROOT_CA_DIR}/${ROOT_CA_FULL_DOMAIN}.crt
ROOT_CA_CHAIN_CRT=${ROOT_CA_DIR}/${ROOT_CA_FULL_DOMAIN}.chain.crt
ROOT_CA_KEY=${ROOT_CA_DIR}/private/${ROOT_CA_FULL_DOMAIN}.key
ROOT_CA_PASSLESS_KEY=${ROOT_CA_DIR}/private/${ROOT_CA_FULL_DOMAIN}.passless.key
ROOT_CA_PASS=${ROOT_CA_DIR}/private/${ROOT_CA_FULL_DOMAIN}.pass
ROOT_CA_P12=${ROOT_CA_DIR}/${ROOT_CA_FULL_DOMAIN}.p12
ROOT_CA_JKS=${ROOT_CA_DIR}/${ROOT_CA_FULL_DOMAIN}.jks

create_ca_dir ${ROOT_CA_DIR}

openssl rand -hex 32 -out ${ROOT_CA_PASS}

openssl req -new -config ${ROOT_CA_CONFIG_FILE} \
-out ${ROOT_CA_CSR} \
-passout pass:$(cat ${ROOT_CA_PASS}) \
-keyout ${ROOT_CA_KEY}

openssl rsa \
-in ${ROOT_CA_KEY} \
-passin pass:$(cat ${ROOT_CA_PASS}) > ${ROOT_CA_PASSLESS_KEY}

openssl ca -selfsign -config ${ROOT_CA_CONFIG_FILE} \
-in ${ROOT_CA_CSR} \
-out ${ROOT_CA_CRT} \
-passin pass:$(cat ${ROOT_CA_PASS}) \
-extensions ca_ext \
-batch

openssl pkcs12 -export -name ${ROOT_CA_NAME} \
-in "${ROOT_CA_CRT}" \
-inkey "${ROOT_CA_KEY}" \
-passin pass:$(cat ${ROOT_CA_PASS}) \
-passout pass:$(cat ${ROOT_CA_PASS}) \
-out "${ROOT_CA_P12}"

cat ${ROOT_CA_CRT} > ${ROOT_CA_CHAIN_CRT}

keytool -importkeystore -srcstoretype pkcs12 \
-srckeystore "${ROOT_CA_P12}" \
-srcstorepass $(cat ${ROOT_CA_PASS}) \
-srcalias ${ROOT_CA_NAME} \
-destkeystore "${ROOT_CA_JKS}" \
-deststorepass $(cat ${ROOT_CA_PASS}) \
-destalias ${ROOT_CA_NAME} -noprompt

rm -f ${ROOT_CA_CSR}

chmod -R a=,u=rX ${ROOT_CA_DIR}/private

}

function generate_sub_ca() {

SUB_CA_CONFIG_FILE=${1:-sub-ca.conf}
PARENT_CA_CONFIG_FILE=${2:-root-ca.conf}

if [[ ! -f ${SUB_CA_CONFIG_FILE} ]]; then
echo "Cannot find Sub CA Config File ${SUB_CA_CONFIG_FILE}"
exit 1
fi

if [[ ! -f ${PARENT_CA_CONFIG_FILE} ]]; then
echo "Cannot find Parent CA Config File ${PARENT_CA_CONFIG_FILE}"
exit 1
fi


SUB_CA_NAME=$(read_config name ${SUB_CA_CONFIG_FILE})
SUB_CA_DOMAIN_SUFFIX=$(read_config domain_suffix ${SUB_CA_CONFIG_FILE})
SUB_CA_FULL_DOMAIN=${SUB_CA_NAME}.${SUB_CA_DOMAIN_SUFFIX}

SUB_CA_DIR=$(pwd)/${SUB_CA_FULL_DOMAIN}

SUB_CA_CSR=${SUB_CA_DIR}/${SUB_CA_FULL_DOMAIN}.csr
SUB_CA_CRT=${SUB_CA_DIR}/${SUB_CA_FULL_DOMAIN}.crt
SUB_CA_CHAIN_CRT=${SUB_CA_DIR}/${SUB_CA_FULL_DOMAIN}.chain.crt
SUB_CA_KEY=${SUB_CA_DIR}/private/${SUB_CA_FULL_DOMAIN}.key
SUB_CA_PASSLESS_KEY=${SUB_CA_DIR}/private/${SUB_CA_FULL_DOMAIN}.passless.key
SUB_CA_PASS=${SUB_CA_DIR}/private/${SUB_CA_FULL_DOMAIN}.pass
SUB_CA_P12=${SUB_CA_DIR}/${SUB_CA_FULL_DOMAIN}.p12
SUB_CA_JKS=${SUB_CA_DIR}/${SUB_CA_FULL_DOMAIN}.jks

PARENT_CA_NAME=$(read_config name ${PARENT_CA_CONFIG_FILE})
PARENT_CA_DOMAIN_SUFFIX=$(read_config domain_suffix ${PARENT_CA_CONFIG_FILE})
PARENT_CA_FULL_DOMAIN=${PARENT_CA_NAME}.${PARENT_CA_DOMAIN_SUFFIX}

PARENT_CA_DIR=$(pwd)/${PARENT_CA_FULL_DOMAIN}

PARENT_CA_CHAIN_CRT=${PARENT_CA_DIR}/${PARENT_CA_FULL_DOMAIN}.chain.crt
PARENT_CA_KEY=${PARENT_CA_DIR}/private/${PARENT_CA_FULL_DOMAIN}.key
PARENT_CA_PASS=${PARENT_CA_DIR}/private/${PARENT_CA_FULL_DOMAIN}.pass

create_ca_dir ${SUB_CA_DIR}

openssl rand -hex 32 -out ${SUB_CA_PASS}

openssl req -new -config ${SUB_CA_CONFIG_FILE} \
-out ${SUB_CA_CSR} \
-passout pass:$(cat ${SUB_CA_PASS}) \
-keyout ${SUB_CA_KEY}

openssl rsa \
-in ${SUB_CA_KEY} \
-passin pass:$(cat ${SUB_CA_PASS}) > ${SUB_CA_PASSLESS_KEY}

openssl ca -config ${PARENT_CA_CONFIG_FILE} \
-in ${SUB_CA_CSR} \
-out ${SUB_CA_CRT} \
-passin pass:$(cat ${SUB_CA_PASS}) \
-extensions sub_ca_ext \
-batch

openssl pkcs12 -export -chain -name ${SUB_CA_NAME} \
-in "${SUB_CA_CRT}" \
-inkey "${SUB_CA_KEY}" \
-passin pass:$(cat ${SUB_CA_PASS}) \
-passout pass:$(cat ${SUB_CA_PASS}) \
-chain -CAfile ${PARENT_CA_CHAIN_CRT} \
-out "${SUB_CA_P12}"

cat ${SUB_CA_CRT} ${PARENT_CA_CHAIN_CRT} > ${SUB_CA_CHAIN_CRT}

keytool -importkeystore -srcstoretype pkcs12 \
-srckeystore "${SUB_CA_P12}" \
-srcstorepass $(cat ${SUB_CA_PASS}) \
-srcalias ${SUB_CA_NAME} \
-destkeystore "${SUB_CA_JKS}" \
-deststorepass $(cat ${SUB_CA_PASS}) \
-destalias ${SUB_CA_NAME} -noprompt

rm -f ${SUB_CA_CSR}

chmod -R a=,u=rX ${SUB_CA_DIR}/private

}

function create_server_cert_dir() {
SERVER_CERT_DIR=${1}

if [[ ! -d ${SERVER_CERT_DIR} ]]; then
    mkdir -p ${SERVER_CERT_DIR}
fi
if [[ ! -d ${SERVER_CERT_DIR}/private ]]; then
    mkdir -p ${SERVER_CERT_DIR}/private
fi

}

function generate_server_cert() {

SERVER_CERT_CONFIG_FILE=${1:-server-cert.conf}
PARENT_CA_CONFIG_FILE=${2:-root-ca.conf}

if [[ ! -f ${SERVER_CERT_CONFIG_FILE} ]]; then
echo "Cannot find Server Cert Config File ${SERVER_CERT_CONFIG_FILE}"
exit 1
fi

if [[ ! -f ${PARENT_CA_CONFIG_FILE} ]]; then
echo "Cannot find Parent CA Config File ${PARENT_CA_CONFIG_FILE}"
exit 1
fi

SERVER_CERT_NAME=$(read_config name ${SERVER_CERT_CONFIG_FILE})
SERVER_CERT_DOMAIN_SUFFIX=$(read_config domain_suffix ${SERVER_CERT_CONFIG_FILE})
SERVER_CERT_FULL_DOMAIN=${SERVER_CERT_NAME}.${SERVER_CERT_DOMAIN_SUFFIX}

SERVER_CERT_DIR=$(pwd)/${SERVER_CERT_FULL_DOMAIN}

SERVER_CERT_CSR=${SERVER_CERT_DIR}/${SERVER_CERT_FULL_DOMAIN}.csr
SERVER_CERT_CRT=${SERVER_CERT_DIR}/${SERVER_CERT_FULL_DOMAIN}.crt
SERVER_CERT_CHAIN_CRT=${SERVER_CERT_DIR}/${SERVER_CERT_FULL_DOMAIN}.chain.crt
SERVER_CERT_KEY=${SERVER_CERT_DIR}/private/${SERVER_CERT_FULL_DOMAIN}.key
SERVER_CERT_PASSLESS_KEY=${SERVER_CERT_DIR}/private/${SERVER_CERT_FULL_DOMAIN}.passless.key
SERVER_CERT_PASS=${SERVER_CERT_DIR}/private/${SERVER_CERT_FULL_DOMAIN}.pass
SERVER_CERT_P12=${SERVER_CERT_DIR}/${SERVER_CERT_FULL_DOMAIN}.p12
SERVER_CERT_JKS=${SERVER_CERT_DIR}/${SERVER_CERT_FULL_DOMAIN}.jks

PARENT_CA_NAME=$(read_config name ${PARENT_CA_CONFIG_FILE})
PARENT_CA_DOMAIN_SUFFIX=$(read_config domain_suffix ${PARENT_CA_CONFIG_FILE})
PARENT_CA_FULL_DOMAIN=${PARENT_CA_NAME}.${PARENT_CA_DOMAIN_SUFFIX}

PARENT_CA_DIR=$(pwd)/${PARENT_CA_FULL_DOMAIN}

PARENT_CA_CHAIN_CRT=${PARENT_CA_DIR}/${PARENT_CA_FULL_DOMAIN}.chain.crt
PARENT_CA_KEY=${PARENT_CA_DIR}/private/${PARENT_CA_FULL_DOMAIN}.key
PARENT_CA_PASS=${PARENT_CA_DIR}/private/${PARENT_CA_FULL_DOMAIN}.pass

create_server_cert_dir ${SERVER_CERT_DIR}

openssl rand -hex 32 -out ${SERVER_CERT_PASS}

openssl req -new -config ${SERVER_CERT_CONFIG_FILE} \
-out ${SERVER_CERT_CSR} \
-passout pass:$(cat ${SERVER_CERT_PASS}) \
-keyout ${SERVER_CERT_KEY}

openssl rsa \
-in ${SERVER_CERT_KEY} \
-passin pass:$(cat ${SERVER_CERT_PASS}) > ${SERVER_CERT_PASSLESS_KEY}

openssl ca -config ${PARENT_CA_CONFIG_FILE} \
-in ${SERVER_CERT_CSR} \
-out ${SERVER_CERT_CRT} \
-passin pass:$(cat ${PARENT_CA_PASS}) \
-extensions server_ext \
-batch

openssl pkcs12 -export -chain -name ${SERVER_CERT_NAME} \
-in "${SERVER_CERT_CRT}" \
-inkey "${SERVER_CERT_KEY}" \
-passin pass:$(cat ${SERVER_CERT_PASS}) \
-passout pass:$(cat ${SERVER_CERT_PASS}) \
-chain -CAfile ${PARENT_CA_CHAIN_CRT} \
-out "${SERVER_CERT_P12}"

cat ${SERVER_CERT_CRT} ${PARENT_CA_CHAIN_CRT} > ${SERVER_CERT_CHAIN_CRT}

keytool -importkeystore -srcstoretype pkcs12 \
-srckeystore "${SERVER_CERT_P12}" \
-srcstorepass $(cat ${SERVER_CERT_PASS}) \
-srcalias ${SERVER_CERT_NAME} \
-destkeystore "${SERVER_CERT_JKS}" \
-deststorepass $(cat ${SERVER_CERT_PASS}) \
-destalias ${SERVER_CERT_NAME} -noprompt

rm -f ${SERVER_CERT_CSR}

chmod -R a=,u=rX ${SERVER_CERT_DIR}/private

}

function generate_root_ca_template(){
ROOT_CA_CONFIG_FILE=${1:-root-ca.conf}

if [[ -f ${ROOT_CA_CONFIG_FILE} ]]; then
echo "Root CA Config File ${ROOT_CA_CONFIG_FILE} already exists"
exit 1
fi


cat <<-'EOF' > ${ROOT_CA_CONFIG_FILE}
# Based on https://www.feistyduck.com/library/openssl-cookbook/online/ch-openssl.html#root-ca-configuration

[default]
name                    = root-ca
domain_suffix           = example.com
full_domain             = ${name}.${domain_suffix}
# aia_url                 = http://${full_domain}/${full_domain}.crt
# crl_url                 = http://${full_domain}/${full_domain}.crl
# ocsp_url                = http://ocsp.${full_domain}:9080
default_ca              = ca_default
name_opt                = utf8,esc_ctrl,multiline,lname,align

[ca_dn]
countryName             = "SG"
organizationName        = "Example"
commonName              = "Root CA"

[ca_default]
home                    = ./${full_domain}
database                = ${home}/db/index
serial                  = ${home}/db/serial
crlnumber               = ${home}/db/crlnumber
certificate             = ${home}/${full_domain}.crt
private_key             = ${home}/private/${full_domain}.key
RANDFILE                = ${home}/private/random
new_certs_dir           = ${home}/certs
unique_subject          = no
copy_extensions         = none
default_days            = 3650
default_crl_days        = 365
default_md              = sha256
policy                  = policy_c_o_match

[policy_c_o_match]
countryName             = match
stateOrProvinceName     = optional
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[req]
default_bits            = 4096
encrypt_key             = yes
default_md              = sha256
utf8                    = yes
string_mask             = utf8only
prompt                  = no
distinguished_name      = ca_dn
req_extensions          = ca_ext

[ca_ext]
basicConstraints        = critical,CA:true
keyUsage                = critical,keyCertSign,cRLSign
subjectKeyIdentifier    = hash

[sub_ca_ext]
# authorityInfoAccess     = @issuer_info
authorityKeyIdentifier  = keyid:always
basicConstraints        = critical,CA:true,pathlen:0
# crlDistributionPoints   = @crl_info
extendedKeyUsage        = clientAuth,serverAuth
keyUsage                = critical,keyCertSign,cRLSign
nameConstraints         = @name_constraints
subjectKeyIdentifier    = hash

# [crl_info]
# URI.0                   = ${crl_url}

# [issuer_info]
# caIssuers;URI.0         = ${aia_url}
# OCSP;URI.0              = ${ocsp_url}

[name_constraints]
permitted;DNS.0=${domain_suffix}
# permitted;DNS.1=example.org
excluded;IP.0=0.0.0.0/0.0.0.0
excluded;IP.1=0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0

# [ocsp_ext]
# authorityKeyIdentifier  = keyid:always
# basicConstraints        = critical,CA:false
# extendedKeyUsage        = OCSPSigning
# keyUsage                = critical,digitalSignature
# subjectKeyIdentifier    = hash

[server_ext]
# authorityInfoAccess     = @issuer_info
authorityKeyIdentifier  = keyid:always
basicConstraints        = critical,CA:false
# crlDistributionPoints   = @crl_info
extendedKeyUsage        = clientAuth,serverAuth
keyUsage                = critical,digitalSignature,keyEncipherment
subjectKeyIdentifier    = hash

[client_ext]
authorityInfoAccess     = @issuer_info
authorityKeyIdentifier  = keyid:always
basicConstraints        = critical,CA:false
# crlDistributionPoints   = @crl_info
extendedKeyUsage        = clientAuth
keyUsage                = critical,digitalSignature
subjectKeyIdentifier    = hash
EOF
echo "Wrote Root CA Template to ${ROOT_CA_CONFIG_FILE}"
}

function generate_sub_ca_template(){
SUB_CA_CONFIG_FILE=${1:-sub-ca.conf}

if [[ -f ${SUB_CA_CONFIG_FILE} ]]; then
echo "Sub CA Config File ${SUB_CA_CONFIG_FILE} already exists"
exit 1
fi

cat <<-'EOF' > ${SUB_CA_CONFIG_FILE}
# Based on https://www.feistyduck.com/library/openssl-cookbook/online/ch-openssl.html#create-a-sub-ca

[default]
name                    = sub-ca
domain_suffix           = example.com
full_domain             = ${name}.${domain_suffix}
# aia_url                 = http://${full_domain}/${full_domain}.crt
# crl_url                 = http://${full_domain}/${full_domain}.crl
# ocsp_url                = http://ocsp.${full_domain}:9081
default_ca              = ca_default
name_opt                = utf8,esc_ctrl,multiline,lname,align

[ca_dn]
countryName             = "SG"
organizationName        = "Example"
commonName              = "Sub CA"

[ca_default]
home                    = ./${full_domain}
database                = ${home}/db/index
serial                  = ${home}/db/serial
crlnumber               = ${home}/db/crlnumber
certificate             = ${home}/${full_domain}.crt
private_key             = ${home}/private/${full_domain}.key
RANDFILE                = ${home}/private/random
new_certs_dir           = ${home}/certs
unique_subject          = no
copy_extensions         = copy
default_days            = 365
default_crl_days        = 30
default_md              = sha256
policy                  = policy_c_o_match

[policy_c_o_match]
countryName             = match
stateOrProvinceName     = optional
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[req]
default_bits            = 4096
encrypt_key             = yes
default_md              = sha256
utf8                    = yes
string_mask             = utf8only
prompt                  = no
distinguished_name      = ca_dn
req_extensions          = ca_ext

[ca_ext]
basicConstraints        = critical,CA:true
keyUsage                = critical,keyCertSign,cRLSign
subjectKeyIdentifier    = hash

[sub_ca_ext]
# authorityInfoAccess     = @issuer_info
authorityKeyIdentifier  = keyid:always
basicConstraints        = critical,CA:true,pathlen:0
# crlDistributionPoints   = @crl_info
extendedKeyUsage        = clientAuth,serverAuth
keyUsage                = critical,keyCertSign,cRLSign
nameConstraints         = @name_constraints
subjectKeyIdentifier    = hash

# [crl_info]
# URI.0                   = ${crl_url}

# [issuer_info]
# caIssuers;URI.0         = ${aia_url}
# OCSP;URI.0              = ${ocsp_url}

[name_constraints]
permitted;DNS.0=example.com
permitted;DNS.1=example.org
excluded;IP.0=0.0.0.0/0.0.0.0
excluded;IP.1=0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0

# [ocsp_ext]
# authorityKeyIdentifier  = keyid:always
# basicConstraints        = critical,CA:false
# extendedKeyUsage        = OCSPSigning
# keyUsage                = critical,digitalSignature
# subjectKeyIdentifier    = hash

[server_ext]
# authorityInfoAccess     = @issuer_info
authorityKeyIdentifier  = keyid:always
basicConstraints        = critical,CA:false
# crlDistributionPoints   = @crl_info
extendedKeyUsage        = clientAuth,serverAuth
keyUsage                = critical,digitalSignature,keyEncipherment
subjectKeyIdentifier    = hash

[client_ext]
# authorityInfoAccess     = @issuer_info
authorityKeyIdentifier  = keyid:always
basicConstraints        = critical,CA:false
# crlDistributionPoints   = @crl_info
extendedKeyUsage        = clientAuth
keyUsage                = critical,digitalSignature
subjectKeyIdentifier    = hash
EOF
echo "Wrote Sub CA Template to ${SUB_CA_CONFIG_FILE}"
}

function generate_server_cert_template(){
SERVER_CERT_CONFIG_FILE=${1:-server-cert.conf}


if [[ -f ${SERVER_CERT_CONFIG_FILE} ]]; then
echo "Server Cert Config File ${SERVER_CERT_CONFIG_FILE} already exists"
exit 1
fi


cat <<-'EOF' > ${SERVER_CERT_CONFIG_FILE}
# Based on https://www.feistyduck.com/library/openssl-cookbook/online/ch-openssl.html#unattended-csr-generation

[default]
name                    = www
domain_suffix           = example.com
full_domain             = ${name}.${domain_suffix}
name_opt                = utf8,esc_ctrl,multiline,lname,align

[dn]
CN = ${full_domain}
emailAddress = admin@${domain_suffix}
O = "Example"
C = "SG"

[req]
default_bits            = 4096
encrypt_key             = yes
default_md              = sha256
utf8                    = yes
string_mask             = utf8only
prompt                  = no
distinguished_name = dn
req_extensions = ext
days = 365

[ext]
subjectAltName = @alt_names

[alt_names]
DNS.0=${full_domain}
DNS.1=${domain_suffix}
EOF
echo "Wrote Server Cert Template to ${SERVER_CERT_CONFIG_FILE}"
}

function generate_wildcard_cert_template(){
WILDCARD_CERT_CONFIG_FILE=${1:-wildcard-cert.conf}


if [[ -f ${WILDCARD_CERT_CONFIG_FILE} ]]; then
echo "Wildcard Cert Config File ${WILDCARD_CERT_CONFIG_FILE} already exists"
exit 1
fi

cat <<-'EOF' > ${WILDCARD_CERT_CONFIG_FILE}
# Based on https://www.feistyduck.com/library/openssl-cookbook/online/ch-openssl.html#creating-certificates-valid-for-multiple-hostnames

[default]
name                    = wildcard
domain_suffix           = example.com
full_domain             = *.${domain_suffix}
name_opt                = utf8,esc_ctrl,multiline,lname,align

[dn]
CN = ${full_domain}
emailAddress = admin@${domain_suffix}
O = "Example"
C = "SG"

[req]
default_bits            = 4096
encrypt_key             = yes
default_md              = sha256
utf8                    = yes
string_mask             = utf8only
prompt                  = no
prompt = no
distinguished_name = dn
req_extensions = ext
days = 365

[ext]
subjectAltName = @alt_names

[alt_names]
DNS.0=${full_domain}
DNS.1=${domain_suffix}
EOF
echo "Wrote Wildcard Cert Template to ${WILDCARD_CERT_CONFIG_FILE}"
}


function print_help() {
cat <<- EOF
Usage: generate.sh root-ca root-ca.conf
Usage: generate.sh sub-ca sub-ca.conf root-ca.conf
Usage: generate.sh cert server-cert.conf parent-ca.conf
Usage: generate.sh root-ca-template root-ca.conf
Usage: generate.sh sub-ca-template sub-ca.conf
Usage: generate.sh server-cert-template server-cert.conf
Usage: generate.sh wildcard-cert-template wildcard-cert.conf
EOF
exit 1
}

if [[ $# -eq 0 ]]; then
    print_help
fi

case ${1} in
    root-ca )
        shift
        generate_root_ca $@
        ;;
    sub-ca )
        shift
        generate_sub_ca $@
        ;;
    cert )
        shift
        generate_server_cert $@
        ;;
    root-ca-template )
        shift
        generate_root_ca_template $@
        ;;
    sub-ca-template )
        shift
        generate_sub_ca_template $@
        ;;
    cert-template )
        shift
        generate_server_cert_template $@
        ;;
    wildcard-cert-template )
        shift
        generate_wildcard_cert_template$@
        ;;
    * )
        print_help
        ;;
esac
