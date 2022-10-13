[![GitHub release][release-img]][release]
[![License][license-img]][license]

<img src="https://github.com/cyberark/KubiScan/blob/assets/kubiscan_logo.png" width="260">  
A tool for scanning Kubernetes cluster for risky permissions in Kubernetes's Role-based access control (RBAC) authorization model.   
The tool was published as part of the "Securing Kubernetes Clusters by Eliminating Risky Permissions" research https://www.cyberark.com/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions/.

## Overview
KubiScan helps cluster administrators identify permissions that attackers could potentially exploit to compromise the clusters.
This can be especially helpful on large environments where there are lots of permissions that can be challenging to track. 
KubiScan gathers information about risky roles\clusterroles, rolebindings\clusterrolebindings, users and pods, automating traditional manual processes and giving administrators the visibility they need to reduce risk.  

## What can it do? 
-	Identify risky Roles\ClusterRoles
-	Identify risky RoleBindings\ClusterRoleBindings
-	Identify risky Subjects (Users, Groups and ServiceAccounts)
-	Identify risky Pods\Containers
-	Dump tokens from pods (all or by namespace)
-	Get associated RoleBindings\ClusterRoleBindings to Role, ClusterRole or Subject (user, group or service account)
-	List Subjects with specific kind ('User', 'Group' or 'ServiceAccount')
-	List rules of RoleBinding or ClusterRoleBinding
-	Show Pods that have access to secret data through a volume or environment variables
-   Get bootstrap tokens for the cluster

## Usage
### Container
Build the Docker image using

```
docker build -t kubiscan .
```

> For usage within Docker, it should be noted that KubiScan expects to be able
> to write to `/KubiScan`. The examples below mount a directory indicated by
> the KUBISCAN_VOLUME variable as a writable volume to the container's
> `/KubiScan` path into which KubiScan will write a config_bak file.

The following variables are recognized by the application:
- `KUBISCAN_CONFIG_PATH` path to the mounted kubeconfig, undefined by default
  and setting this skips the previous behaviour (see
  [source][running-in-docker]) and renders to `KUBISCAN_CONFIG_BACKUP_PATH` and
  `KUBISCAN_VOLUME_PATH` obsolete as the branches utilizing these become
  unreachable.
- `KUBISCAN_CONFIG_BACKUP_PATH` path to the config_bak path, defaults to
  `/KubiScan/config_bak`
- `KUBISCAN_VOLUME_PATH` defaults to `/tmp`

[running-in-docker]: https://github.com/cyberark/KubiScan/blob/2531bbdd268c9a7c729a2e6826590516c6aab201/api/api_client.py#L59

#### With `~/.kube/config` file
This should be executed within the **Master** node where the config file is located:

```
docker run -it --rm \
  -v ~/.kube/config:/tmp/kubiscan/kubeconfig.yaml:ro \
  -e KUBISCAN_CONFIG_PATH=/tmp/kubiscan/kubeconfig.yaml \
  kubiscan <command>
```

Replace `<command>` with the actual arguments to the KubiScan application that you want to run.

```
# Example running `kubiscan --help`
docker run -it --rm \
  -v ~/.kube/config:/tmp/kubiscan/kubeconfig.yaml:ro \
  -e KUBISCAN_CONFIG_PATH=/tmp/kubiscan/kubeconfig.yaml \
  kubiscan --help
```

```
# Example running `kubiscan --all`
docker run -it --rm \
  -v ~/.kube/config:/tmp/kubiscan/kubeconfig.yaml:ro \
  -e KUBISCAN_CONFIG_PATH=/tmp/kubiscan/kubeconfig.yaml \
  kubiscan --all
```

#### With service account token (good from remote)
Some functionality requires a **privileged** service account with the following permissions:  
- **resources**: `["roles", "clusterroles", "rolebindings", "clusterrolebindings", "pods", "secrets"]`  
  **verbs**: `["get", "list"]`  
- **resources**: `["pods/exec"]`  
  **verbs**: `["create", "get"]`  

But most of the functionalities are not, so you can use this settings for limited service account:  
It can be created by running:
```
kubectl apply -f - << EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kubiscan-sa
  namespace: default
---
apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token
metadata:
  name: kubiscan-sa-secret
  annotations:
    kubernetes.io/service-account.name: kubiscan-sa
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata: 
  name: kubiscan-clusterrolebinding
subjects: 
- kind: ServiceAccount 
  name: kubiscan-sa
  namespace: default
  apiGroup: ""
roleRef: 
  kind: ClusterRole
  name: kubiscan-clusterrole
  apiGroup: ""
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata: 
  name: kubiscan-clusterrole
rules: 
- apiGroups: ["*"]
  resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings", "pods"]
  verbs: ["get", "list"]
EOF
```

Save the service account's token to a file:  
`kubectl get secrets $(kubectl get sa kubiscan-sa -o=jsonpath='{.secrets[0].name}') -o=jsonpath='{.data.token}' | base64 -d > token`

> Note that a valid kubeconfig can be configured to utilize the token by
> updating the `users` object to contain the appropriate `name` and
> `user.token` values.  Arguably, the usage of kubeconfig files is a more
> idiomatic and user-friendly approach to connecting to Kubernetes clusters.

Spawn a Bash shell into the container:
```
docker run -it --rm \
  -v ${TOKEN_PATH}/token:/tmp/kubiscan/token:ro \
  -v ${KUBISCAN_VOLUME}:/KubiScan \
  --entrypoint=bash kubiscan
```

> Note that the directory represented by the `KUBISCAN_VOLUME` variable should
> be writable because KubiScan, when running inside a Docker container, expects
> a `/KubiScan/config_bak` file (see [source][running-in-docker]) and will
> attempt to create /KubiScan/config_bak when missing.

In the shell you will be able to to use kubiscan like that:   
`kubiscan -ho <master_ip:master_port> -t /token <command>`  

For example:   
`kubiscan -ho 192.168.21.129:8443 -t /token -rs`  

Notice that you can also use the certificate authority (ca.crt) to verify the SSL connection:  
`docker run -it --rm -v $PWD/token:/token -v <ca_path>/ca.crt:/ca.crt cyberark/kubiscan`  

Inside the container:    
`kubiscan -ho <master_ip:master_port> -t /token -c /ca.crt <command>`  

To remove the privileged service account, run the following commands: 
```
kubectl delete clusterroles kubiscan-clusterrole  
kubectl delete clusterrolebindings kubiscan-clusterrolebinding   
kubectl delete sa kubiscan-sa   
```

### Directly with Python3
#### Prerequisites:
-	__Python 3.6+__
-	__Pip3__
-	[__Kubernetes Python Client__](https://github.com/kubernetes-client/python) 
-	[__Prettytable__](https://pypi.org/project/PTable)
-	__openssl__ (built-in in ubuntu) - used only for join token

#### Example for installation on Ubuntu:
```
apt-get update  
apt-get install -y python3 python3-pip 
pip3 install kubernetes  
pip3 install PTable
```

Run `alias kubiscan='python3 /<KubiScan_folder>/KubiScan.py'` to use `kubiscan`.  

After installing all of the above requirements you can run it in two different ways:  
#### From the Master node:
On the Master node where `~/.kube/config` exist and all the relevant certificates, simply run:  
`kubiscan <command>`  
For example: `kubiscan -rs` will show all the risky subjects (users, service accounts and groups).  

#### From a remote host:
To use this tool from a remote host, you will need a **privileged** service account like we explained in the container section.  
After you have the token inside a file you can run:  
`kubiscan -ho <master_ip:master_port> -t /token <command>`  

## Examples  
To see all the examples, run `python3 KubiScan.py -e` or from within the container `kubiscan -e`.  

## Demo  
A small example of KubiScan usage: 
<p><a href="https://cyberark.wistia.com/medias/0lt642okgn?wvideo=0lt642okgn"><img src="https://github.com/cyberark/KubiScan/blob/assets/kubiscan_embeded.png?raw=true" width="600"></a></p>

## Risky Roles YAML
There is a file named `risky_roles.yaml`. This file contains templates for risky roles with priority.    
Although the kind in each role is `Role`, these templates will be compared against any Role\ClusterRole in the cluster.  
When each of these roles is checked against a role in the cluster, it checks if the role in the cluster contains the rules from the risky role. If it does, it will be marked as risky.  
We added all the roles we found to be risky, but because each one can define the term "risky" in a different way, you can modify the file by adding\removing roles you think are more\less risky.  

## ❤️ Showcase  
* Presented at RSA 2020 ["Compromising Kubernetes Cluster by Exploiting RBAC Permissions"](https://www.youtube.com/watch?v=1LMo0CftVC4)
* Presented at RSA 2022 ["Attacking and Defending Kubernetes Cluster: Kubesploit vs KubiScan"](https://www.youtube.com/watch?v=xRqYSDKi6a0)
* Article by PortSwigger ["KubiScan: Open source Kubernetes security tool showcased at Black Hat 2020"](https://portswigger.net/daily-swig/kubiscan-open-source-kubernetes-security-tool-showcased-at-black-hat-2020)
* 

## License
Copyright (c) 2020 CyberArk Software Ltd. All rights reserved  
This repository is licensed under GPL-3.0 License - see [`LICENSE`](LICENSE) for more details.

## References:
For more comments, suggestions or questions, you can contact Eviatar Gerzi ([@g3rzi](https://twitter.com/g3rzi)) and CyberArk Labs.

[release-img]: https://img.shields.io/github/release/cyberark/kubiscan.svg
[release]: https://github.com/cyberark/kubiscan/releases

[license-img]: https://img.shields.io/github/license/cyberark/kubiscan.svg
[license]: https://github.com/cyberark/kubiscan/blob/master/LICENSE
