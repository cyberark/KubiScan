#!/bin/bash
GREEN='\033[3;92m'
BCYAN='\033[1;96m'
UCYAN='\033[4;96m'
NO_COLOR='\033[0m'

if [ "$1" = "-h" ]; then
  echo -e "${UCYAN}How to run unit-test:${NO_COLOR}"
  echo -e "${BCYAN}$(cat readme)${NO_COLOR}"
  exit 0
fi

DEFAULT_SECRET=$(kubectl get sa default -o=jsonpath='{.secrets[0].name}')
echo -e "${GREEN}Creating kubiscan-sa...${NO_COLOR}"
kubectl apply -f kubiscan-sa

echo -e "${GREEN}Creating kubiscan-sa2...${NO_COLOR}"
kubectl apply -f kubiscan-sa2

# Function to wait for the secret to be created
wait_for_secret() {
  local sa_name=$1
  local secret_name=""
  
  # Retry up to 10 times, waiting for 1 second between each retry
  for i in {1..30}; do
    secret_name=$(kubectl get sa $sa_name -o=jsonpath='{.secrets[0].name}')
    if [ -n "$secret_name" ]; then
      break
    fi
    echo "Waiting for secret for service account $sa_name..."
    sleep 2
  done
  
  if [ -z "$secret_name" ]; then
    echo "Error: Secret for service account $sa_name not found after waiting."
    exit 1
  fi
  
  echo "$secret_name"
}

# Wait for the secrets to be available
KUBISCAN_SA_SECRET=$(wait_for_secret kubiscan-sa)
KUBISCAN_SA2_SECRET=$(wait_for_secret kubiscan-sa2)

echo -e "${BCYAN}kubiscan-sa secret: $KUBISCAN_SA_SECRET, kubiscan-sa2 secret: $KUBISCAN_SA2_SECRET ${NO_COLOR}"

echo -e "${GREEN}Creating test1-yes pod...${NO_COLOR}"
kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test1-yes
spec:
  serviceAccountName: kubiscan-sa
  containers:
  - name: test1-yes
    image: nginx
EOF

echo -e "${GREEN}Creating test5-yes pod...${NO_COLOR}"
kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test5a-yes
  namespace: default
spec:
  serviceAccountName: kubiscan-sa
  containers:
  - image: nginx
    name: test5ac1-no
    volumeMounts:
    - name: secret-volume
      readOnly: true
      mountPath: "/var/run/secrets/kubernetes.io/serviceaccount"
  - image: nginx
    name: test5ac2-yes
  volumes:
  - name: secret-volume
    secret:
      secretName: "$DEFAULT_SECRET"
EOF

echo -e "${GREEN}Creating test8-yes pod...${NO_COLOR}"
kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test8-yes
  namespace: default
spec:
  serviceAccountName: kubiscan-sa
  containers:
  - image: nginx
    name: test8c-yes
    volumeMounts:
    - name: secret-volume
      readOnly: true
      mountPath: "/var/run/secrets/kubernetes.io/serviceaccount"
    - name: secret-volume2
      mountPath: "/var/run/secrets/tokens"
  volumes:
  - name: secret-volume
    secret:
      secretName: "$KUBISCAN_SA_SECRET"
  - name: secret-volume2
    secret:
      secretName: "$KUBISCAN_SA2_SECRET"
EOF

echo -e "${GREEN}Creating test1-no pod...${NO_COLOR}"
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test1-no
spec:
  serviceAccountName: default
  containers:
  - name: test1-no
    image: nginx
EOF

echo -e "${GREEN}Creating test2b-no pod...${NO_COLOR}"
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test2b-no
spec:
  serviceAccountName: default
  volumes:
  - name: secret-volume
    secret:
      secretName: "$KUBISCAN_SA2_SECRET"
  containers:
  - name: test2b-no
    image: nginx
    volumeMounts:
    - name: secret-volume
      readOnly: true
      mountPath: "/var/run/secrets/kubernetes.io/serviceaccount"
EOF

echo -e "${GREEN}Creating test3-yes pod...${NO_COLOR}"
kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata: 
  name: test3-yes
  namespace: default
spec: 
  containers: 
    - 
      image: nginx
      name: test3-yes
      volumeMounts: 
        - 
          mountPath: /var/run/secrets/tokens2
          name: sa
        - 
          mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          name: secret-volume
          readOnly: true
  serviceAccountName: default
  volumes: 
    - 
      name: sa
      projected: 
        sources: 
          - 
            serviceAccountToken: 
              audience: some-oidc-audience
              expirationSeconds: 86400
              path: sa
    - 
      name: secret-volume
      secret: 
        secretName: "$KUBISCAN_SA_SECRET"
EOF

echo -e "${GREEN}Creating test6-yes pod...${NO_COLOR}"
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test6-yes
  namespace: default
spec:
  serviceAccountName: kubiscan-sa
  containers:
  - image: nginx
    name: test6a-yes
  - image: nginx
    name: test6b-yes
EOF


echo -e "${GREEN}Creating test7-yes pod...${NO_COLOR}"
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test7-yes
  namespace: default
spec:
  serviceAccountName: kubiscan-sa
  containers:
  - image: nginx
    name: test7c1-no
    volumeMounts:
    - name: secret-volume
      readOnly: true
      mountPath: "/var/run/secrets/kubernetes.io/serviceaccount"
    - name: not-token-secret
      mountPath: "/var/run/secrets/tokens"
  - image: nginx
    name: test7c2-yes
  volumes:
  - name: secret-volume
    secret:
      secretName: "${KUBISCAN_SA2_SECRET}"
  - name: not-token-secret
    secret:
      secretName: mysecret
EOF