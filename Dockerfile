# Default to the Docker Hub container registry
ARG DOCKER_REGISTRY=index.docker.io

# Default to the official Python Debian image
ARG PYTHON_IMAGE=${DOCKER_REGISTRY}/python:3.8.0-slim-buster


FROM ${PYTHON_IMAGE} AS build-image

WORKDIR /tmp/build-kubiscan
COPY requirements.txt requirements.txt

# The default image provides `pip`, `pip3`, `python` and `python3` commands and
# for portability's sake, the `pip3` and `python3` names will be used in this
# configuration.

# Install Python dependencies from requirements.txt
# As customary with Python projects, the requirements.txt, when provided,
# should contain all packages necessary to run the Python source for the
# project. As such changes to the dependencies would merely warrant a change to
# the requirements.txt file, while the Dockerfile files remain unaffected.
RUN pip3 install -r requirements.txt


FROM ${PYTHON_IMAGE} AS run-image
# Copy Python packages installed in the build stage
COPY --from=build-image /usr/local /usr/local

# Copy source
COPY . /opt/kubiscan

# Create kubiscan executable shortcut for all users
# NOTE that this image does not default to using this shortcut but rather
# resorts to directly starting the KubiScan Python script. It may prove useful
# to remove this shortcut altogether unless end-users are expected to spawn a
# Bash inside the resulting container in which case the `kubiscan` shortcut
# will come in handy.
RUN set -ex \
  && echo 'python3 /opt/kubiscan/KubiScan.py $@' > /usr/local/bin/kubiscan \
  && chmod a+x /usr/local/bin/kubiscan \
  && which kubiscan

# Create a non-root user and group
RUN set -ex \
  && addgroup kubiscan \
  && adduser \
    --no-create-home \
    --disabled-password \
    --gecos ',,,,' \
    --ingroup kubiscan \
    --disabled-login \
    kubiscan \
  && > /var/log/faillog \
  && > /var/log/lastlog

# Environment variable to know if running in a container
ENV RUNNING_IN_A_CONTAINER=true