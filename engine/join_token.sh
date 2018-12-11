MASTER_SERVER_IP="$1"
MASTER_SERVER_PORT="$2"

#CA_CRT_PATH="/etc/kubernetes/pki/ca.crt"
CA_CRT_PATH="$3"

TOKEN="$4"

SHA=`openssl x509 -pubkey -in $CA_CRT_PATH | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //'`

# Might need `sudo`
#TOKEN_LIST=`kubeadm token list`

#TOKEN=`echo $TOKEN_LIST | cut -d ' ' -f8`

echo "kubeadm join --token $TOKEN $MASTER_SERVER_IP:$MASTER_SERVER_PORT --discovery-token-ca-cert-hash sha256:$SHA"