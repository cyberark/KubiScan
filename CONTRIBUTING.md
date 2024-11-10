# Contributing
Thank you for considering contributing to KubiScan! We welcome contributions to improve this project.
For general contribution and community guidelines, please see the [community repo](https://github.com/cyberark/community).

## Contributing

1. [Fork the project](https://help.github.com/en/github/getting-started-with-github/fork-a-repo)
2. [Clone your fork](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/cloning-a-repository)
3. Make local changes to your fork by editing files
3. [Commit your changes](https://help.github.com/en/github/managing-files-in-a-repository/adding-a-file-to-a-repository-using-the-command-line)
4. [Push your local changes to the remote server](https://help.github.com/en/github/using-git/pushing-commits-to-a-remote-repository)
5. [Create new Pull Request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request-from-a-fork)

From here your pull request will be reviewed and once you've responded to all
feedback it will be merged into the project. Congratulations, you're a
contributor!

## Development
To start developing and testing using our development scripts ,
the following tools need to be installed:
  - Docker
  - Minikube (or any other local Kubernetes setup)

### Running tests
```shell
[1] Commit and push your changes to your repository.
[2] Make sure docker is installed on the host.
[3] Start MiniKube.
[4] Type the following commands:
    "cd /tmp"
    "git clone <your repo>"
    "cd KubiScan/unit_test/"
    "./kubectl_apply.sh"
[5] For the unit-test run the following command:
    python3 -m pytest -v unit_test.py
```

## Releases
Maintainers only should create releases. Follow these steps to prepare for a release.

### Pre-requisites

1. Review recent commits and ensure the [changelog](CHANGELOG.md) includes all relevant changes, with references to GitHub issues or PRs when applicable.
2. Verify that any updated dependencies are accurately reflected in the [NOTICES](NOTICES.txt).
3. Confirm that required documentation is complete and has been approved.
4. Scan the project for vulnerabilities

### Release and Promote

1. Merging to the main branch will trigger an automated release build. Successful builds can be promoted at a later time.
2. Use build parameters in CI/CD tools to promote a release or manually trigger additional builds if needed.
###
Thank you for contributing to KubiScan!






