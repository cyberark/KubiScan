#!/bin/bash
GREEN='\033[3;92m'
BCYAN='\033[1;96m'
UCYAN='\033[4;96m'
NO_COLOR='\033[0m'


if [ "$1" = "-h" ];
then
  echo -e "${UCYAN}How to run unit-test:${NO_COLOR}"
  echo -e "${BCYAN}$(cat readme)${NO_COLOR}"
  exit 0
fi

DEFAULT_SECRET=$(kubectl get sa default -o=jsonpath='{.secrets[0].name}')
echo -e "${GREEN}Creating kubiscan-sa...${NO_COLOR}"
kubectl apply -f kubiscan-sa
echo -e "${GREEN}Creating kubiscan-sa2...${NO_COLOR}"
kubectl apply -f kubiscan-sa2
KUBISCAN_SA_SECRET=$(kubectl get sa kubiscan-sa -o=jsonpath='{.secrets[0].name}')
KUBISCAN_SA2_SECRET=$(kubectl get sa kubiscan-sa2 -o=jsonpath='{.secrets[0].name}')
echo -e "${BCYAN}kubiscan-sa secret: "$KUBISCAN_SA_SECRET", kubiscan-sa2 secret: "$KUBISCAN_SA2_SECRET ${NO_COLOR}""

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