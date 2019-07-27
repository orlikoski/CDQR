# Use the official Docker Hub Ubuntu 18.04 base image
FROM ubuntu:18.04

# Setup install environment and Timesketch dependencies
RUN apt-get update && apt-get -y install apt-transport-https \
    curl \
    git \
    libffi-dev \
    lsb-release \
    python3-dev \
    python3-pip \
    python3-psycopg2

RUN curl -sS https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add - && \
    VERSION=node_8.x && \
    DISTRO="$(lsb_release -s -c)" && \
    echo "deb https://deb.nodesource.com/$VERSION $DISTRO main" > /etc/apt/sources.list.d/nodesource.list && \
    curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add - && \
    echo "deb https://dl.yarnpkg.com/debian/ stable main" > /etc/apt/sources.list.d/yarn.list

# Install Plaso
RUN apt-get -y install software-properties-common && \
    add-apt-repository ppa:gift/stable && \
    apt-get update && \
    apt-get -y install python-plaso plaso-tools nodejs yarn && \
    apt-get -y dist-upgrade

# Build and Install Timesketch from GitHub Master with Pip
RUN git clone https://github.com/google/timesketch.git /tmp/timesketch && \
    cd /tmp/timesketch && git checkout d8c3ac17abdbf06d23614e0b68cff3bb94224c35 && yarn install && yarn run build && \
    sed -i -e '/pyyaml/d' /tmp/timesketch/requirements.txt && \
    pip3 install /tmp/timesketch/

# Download and install CDQR
RUN git clone https://github.com/orlikoski/CDQR.git /tmp/CDQR && \
    cd /tmp/CDQR && git checkout tags/5.0 && \
    cp /tmp/CDQR/src/cdqr.py /usr/local/bin/cdqr.py && \
    rm -rf /tmp/* && \
    chmod a+x /usr/local/bin/cdqr.py

# Cleanup apt cache
RUN apt-get -y autoremove --purge && \
    apt-get -y clean && \
    apt-get -y autoclean 

# Load the entrypoint script to be run later
ENTRYPOINT ["/usr/local/bin/cdqr.py"]
