#!/bin/bash

# Getting the kubeconfig path.
kube_config="$1"
aws_dir="$2"
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
docker run -t -d --rm --name kubiscan_container -e CONF_PATH=/config --network host g3rzi/kubiscan

# The new container id.
kubiscan_container_id=$( docker ps -a -f "name=kubiscan_container" -q)

# If the argument is empty, enter.
if [ -n "$aws_dir" ];
then
	echo "Copying aws folder"
	docker exec "$kubiscan_container_id" bash -c "mkdir -p /home/kubiscan"
	docker cp  "$aws_dir" "$kubiscan_container_id":/home/kubiscan/.aws/
fi


# Get the path to the certificate auth file
certificate_auth=$(grep -i "certificate-authority:" "$kube_config" | sed 's/certificate-authority://g' | sed 's/ //g')
# 'certificate_auth%/*' delete everything after the last '/'
if [ -n "$certificate_auth" ];
then
  certificate_auth_path="/tmp${certificate_auth%/*}"
  echo "Creating folders: $certificate_auth_path"
  docker exec -it "$kubiscan_container_id" bash -c "mkdir -p $certificate_auth_path"
fi
# Get all the paths of the cert files in the kube config file.
cert_array=$(grep -i "client-certificate:" "$kube_config" | sed 's/client-certificate://g' | sed 's/ //g')
# Get all the paths of the key files in the kube config file.
key_array=$(grep -i "client-key:" "$kube_config" | sed 's/client-key://g' | sed 's/     //g')

#Create all the paths for the 'mkdir' command in the container.
if [ -n "$cert_array" ];
then
  echo "$cert_array"
  raw_cert_paths=""
  for var in $cert_array:
  do
	  # 'var%/*' delete everything after the last '/'
	  raw_cert_paths="$raw_cert_paths /tmp${var%/*}"
  done
fi

if [ -n "$key_array" ];
then
  raw_key_paths=""
  for path in $key_array:
  do
	  # 'var%/*' delete everything after the last '/'
	  raw_key_paths="$raw_key_paths /tmp${path%/*}"
  done
  all_paths="$raw_cert_paths $raw_key_paths"
  echo "Creating folders: $all_paths"
  docker exec -it "$kubiscan_container_id" bash -c "mkdir -p $all_paths"
fi


if [ -n "$cert_array" ];
then
  # Copy all the certificates to the container
  for cert_file in $cert_array
  do
    # Copy them to tmp folder
    echo "Copying $cert_file to /tmp$cert_file"
    docker cp "$cert_file" "$kubiscan_container_id":/tmp"$cert_file"
  done
fi

if [ -n "$key_array" ];
  then
  # Copy all keys to the container
  for key_file in $key_array
  do
    # Copy them to tmp folder
    echo "Copying $key_file to /tmp $key_file"
    docker cp "$key_file" "$kubiscan_container_id":/tmp"$key_file"
  done
fi

# Copy kube config file
echo "Copying $kube_config to /tmp"
docker cp "$kube_config" "$kubiscan_container_id:/tmp"

# Copy certificate auth file

if [ -n "$certificate_auth" ];
then
  echo "Copying $certificate_auth to $certificate_auth"
  docker cp "$certificate_auth" "$kubiscan_container_id":/tmp/"$certificate_auth"
fi
# Giving permissions to /tmp and opt/KubiScan
# The "-f" in chmod will suppress the errors
docker exec -it "$kubiscan_container_id" bash -c "chmod -fR 777 /tmp /opt/kubiscan /home/kubiscan"
docker exec -it --user kubiscan "$kubiscan_container_id" bash

