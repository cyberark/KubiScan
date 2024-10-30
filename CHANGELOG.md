# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).


## [v1.6] - 2023-01-27
- Replaced Added support to match case match case with if else to support Python versions below 3.10 (#69 by @kamal2222ahmed)
- Failed chmod when not specifying AWS info (#66 & #67 by @elreydetoda)
- Adding support to AKS and options to CVE scan (#65 by @2niknatan)
- Adding CVE scan and unittest (#64 by @2niknatan)
- Adding flags (-o, -q, -j and -nc) to enhance the output (#63 by @2niknatan)
- Changing the risky pods function (#62 by @2niknatan)
- Adding unit tests (#55 by @2niknatan)
- Supporting eks in docker container (#54 by @2niknatan)
- Printing error message when no kind was entered to '-aars' flag (#53 by @2niknatan)
- Fixing duplicates in '-rp' flag (#52 & #50)
- Fix typo in api_client.py (#51 by @AlonBenHorin)
- Fixing '-rp' flag by adding logic so it can print several Service Accounts (#49 by @2niknatan)
- Adding secret creation to support version +1.24
- Fixing hang in some environments (#47 by @2niknatan)
- Fixing the path to '/opt/kubiscan/config_bak' like in the Dockerfile (#46 by @2niknatan)
- Adding an environment variable to docker file, fixing -td flag and catching exceptions and adding tag to docker image (#45 by @2niknatan)
- Update docker_run.sh
- Adding catch exception and fix non existing key bug (#41 by @AlonBenHorin)
- Fixing pull request #18 and adding bash script to run a container (#40 by @AlonBenHorin)
- Minor change in the check for running inside a container
- Added support to kubeconfig in the API client (by @g3rzi)
- Simplify dockerfile + Parameterize paths (#18 by @vidbina)

## [v1.5] - 2022-09-21
- Fix 'NoneType' object is not iterable and always connection to localhost (#24)
- Resolve errors encountered running kubiscan in openshift and from a container image (#23)
- Handle pod.spec.volumes with None (#20)
- Fix TLS warnings when using a token (#19)
- Fix SyntaxWarning for 'is not' with literals
- Fix missing namespace for service account (#10)
- Fix --pods-secrets-env example (#17)
- Support Py version where async is keyword: fix #11 (#14)
- Added fix for container check in MacOS (#15)
- Use yaml.safe_load instead of yaml.load (#16)
  
## [v1.4] - 2020-01-14
- Added check for hostPID and hostIPC
- Added parsing for pod's spec for hostPID nad hostIPC
- Added support on hostNetwork nad hostPorts
- Added printing of hostPorts and hostNetwork information
- Removed debug printing for pod name
- Fixed wrong indents in risk YAML file
- Added support on hostPaths in containers
- Added support to printing volumes with hostPaths mounted to container
- Added the mounted path inside the container

## [v1.3] - 2019-07-24
- Fix checking if inside a docker container
- Fix bug to get RoleBindings of "User" subjects
- Added catch for error 404 in function get_roles_associated_to_subject

## [v1.2] - 2019-04-10
- New switch (-pp\--privileged-pods) to get privileged pods\containers
- Added pod's namespace to risky pods
  
## [v1.1] - 2019-03-28
- New switch (-d\--deep) to read tokens from containers
- Added option to read token from ETCD
- Added missing verb in kubiscan-sa token permissions
- Fixed wrong resource name in kubiscan-sa token permissions
- New switch for priority filtering
- Support for different contexts
- Dockerfile support for lightweight alpine image
- Strip newline from files

## [v1.0] - 2019-03-28
- Initial version
