#!/bin/bash

# Getting the kubeconfig path.
kube_config="$1"

# Check if the file is empty
if [ -z "$kube_config" ];
then
  echo "Please provide kube config path"
  exit 1
fi

# Check if the file exists
if ! test -f "$kube_config"; then
  echo "File of directory does not exist"
  exit 1
fi

# Running the container.
docker run -t -d --rm --name kubiscan_container -e CONF_PATH=/config --network host natan2nik/kubiscan
# docker run -t -d --rm --name kubiscan_container -e CONF_PATH=/config --network host --detach kubiscan bash -c "sleep infinity"

# The new container id.
kubiscan_container_id=$( docker ps -a -f "name=kubiscan_container" -q)

# Get the path to the certificate auth file
certificate_auth=$(grep -i "certificate-authority:" "$kube_config" | sed 's/certificate-authority://g' | sed 's/ //g')

# 'certificate_auth%/*' delete everything after the last '/'
certificate_auth_path="/tmp${certificate_auth%/*}"

# Get all the paths of the cert files in the kube config file.
cert_array=$(grep -i "client-certificate:" "$kube_config" | sed 's/client-certificate://g' | sed 's/ //g')

# Get all the paths of the key files in the kube config file.
key_array=$(grep -i "client-key:" "$kube_config" | sed 's/client-key://g' | sed 's/     //g')

#Create all the paths for the 'mkdir' command in the container.
raw_cert_paths=""
for var in $cert_array:
do
	# 'var%/*' delete everything after the last '/' 
	raw_cert_paths="$raw_cert_paths /tmp${var%/*}"
done
raw_key_paths=""
for path in $key_array:
do
	# 'var%/*' delete everything after the last '/'
	raw_key_paths="$raw_key_paths /tmp${path%/*}"
done

all_paths="$raw_cert_paths $raw_key_paths $certificate_auth_path"
echo "Creating folders: $all_paths"
docker exec -it "$kubiscan_container_id" bash -c "mkdir -p $all_paths"

# Copy all the certificates to the container
for cert_file in $cert_array
do
	# Copy them to tmp folder
	echo "Copying $cert_file to /tmp$cert_file"
	docker cp "$cert_file" "$kubiscan_container_id":/tmp"$cert_file"
done

# Copy all keys to the container
for key_file in $key_array
do
	# Copy them to tmp folder
	echo "Copying $key_file to /tmp $key_file"
	docker cp "$key_file" "$kubiscan_container_id":/tmp"$key_file"
done

# Copy kube config file
echo "Copying $kube_config to /tmp"
docker cp "$kube_config" "$kubiscan_container_id:/tmp"

# Copy certificate auth file
echo "Copying $certificate_auth to $certificate_auth"
docker cp "$certificate_auth" "$kubiscan_container_id":/tmp/"$certificate_auth"
# Giving permissions to /tmp and opt/KubiScan
docker exec -it "$kubiscan_container_id" bash -c "chmod -R 777 /tmp /opt/kubiscan"
docker exec -it --user kubiscan "$kubiscan_container_id" bash