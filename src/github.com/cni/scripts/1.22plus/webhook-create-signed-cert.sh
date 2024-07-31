#!/bin/bash

set -x
set -e

usage() {
    cat <<EOF
Generate certificate suitable for use with an validate webhook service.

This script uses k8s' CertificateSigningRequest API to a generate a
certificate signed by k8s CA suitable for use with validate webhook
services. This requires permissions to create and approve CSR. See
https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster for
detailed explantion and additional instructions.

The server key/cert k8s CA cert are stored in a k8s secret.

usage: ${0} [OPTIONS]

The following flags are required.

       --service          Service name of webhook.
       --namespace        Namespace where webhook service and secret reside.
       --secret           Secret name for CA certificate and server certificate/key pair.
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case ${1} in
        --service)
            service="$2"
            shift
            ;;
        --secret)
            secret="$2"
            shift
            ;;
        --namespace)
            namespace="$2"
            shift
            ;;
        *)
            usage
            ;;
    esac
    shift
done

[ -z ${service} ] && service=sdnc-net-master-webhook
[ -z ${secret} ] && secret=sdnc-net-webhook-certs
[ -z ${namespace} ] && namespace=kube-system

if [ ! -x "$(command -v cfssl)" ]; then
    echo "cfssl not found"
    exit 1
fi

if [ ! -x "$(command -v cfssljson)" ]; then
    echo "cfssljson not found"
    exit 1
fi

csrName=${service}.${namespace}
tmpdir=$(mktemp -d)
echo "creating certs in tmpdir ${tmpdir} "

cd $tmpdir

echo "cd tmpdir ${tmpdir} "

#Create certificate signing request
cat <<EOF | cfssl genkey - | cfssljson -bare server
{
  "hosts": [
    "${service}.${namespace}.svc"
  ],
  "CN": "${service}.${namespace}.svc",
  "key": {
    "algo": "ecdsa",
    "size": 256
  }
}
EOF

# clean-up any previously created CSR for our service. Ignore errors if not present.
kubectl delete csr ${csrName} 2>/dev/null || true

#Create a certificate signing request (CSR) object and send it to Kubernetes API
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: sdnc-net-master-webhook.kube-system
spec:
  request: $(cat server.csr | base64 | tr -d '\n')
  signerName: example.com/serving
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF

# verify CSR has been created
while true; do
    kubectl get csr ${csrName}
    if [ "$?" -eq 0 ]; then
        break
    fi
done


#approve and fetch the signed certificate
kubectl certificate approve ${csrName}

#Issue certificate
cat > server-signing-config.json  <<EOF
{
    "signing": {
        "default": {
            "usages": [
                "digital signature",
                "key encipherment",
                "server auth"
            ],
            "expiry": "876000h",
            "ca_constraint": {
                "is_ca": false
            }
        }
    }
}
EOF
#Copy ca certificate
cakey=/etc/kubernetes/pki/ca.key
cacrt=/etc/kubernetes/pki/ca.crt
if [ ! -e $cakey ]; then
    echo "${cakey} not found"
    exit 1
else
    cp /etc/kubernetes/pki/ca.key ca-key.pem
fi

if [ ! -e $cacrt ]; then
    echo "${cacrt} not found"
    exit 1
else
    cp /etc/kubernetes/pki/ca.crt ca.pem
fi

kubectl get csr ${csrName}  -o jsonpath='{.spec.request}' | base64 --decode |   cfssl sign -ca ca.pem -ca-key ca-key.pem -config server-signing-config.json - |   cfssljson -bare ca-signed-server

#Upload signature certificate
kubectl get csr ${csrName}  -o json | jq '.status.certificate = "'$(base64 ca-signed-server.pem | tr -d '\n')'"' | kubectl replace --raw /apis/certificates.k8s.io/v1/certificatesigningrequests/${csrName}/status -f -

# verify certificate has been signed
for x in $(seq 10); do
    serverCert=$(kubectl get csr ${csrName} -o jsonpath='{.status.certificate}')
    if [[ ${serverCert} != '' ]]; then
        break
    fi
    sleep 1
done
if [[ ${serverCert} == '' ]]; then
    echo "ERROR: After approving csr ${csrName}, the signed certificate did not appear on the resource. Giving up after 10 attempts." >&2
    exit 1
fi

#Load the certificate and use it
kubectl get csr ${csrName}   -o jsonpath='{.status.certificate}' | base64 --decode > server-crt.pem

#Generate secret
kubectl delete secret ${secret} -nkube-system 2>/dev/null || true
kubectl create secret generic ${secret} --from-file=key.pem=server-key.pem --from-file=cert.pem=server-crt.pem -n kube-system  -o yaml

