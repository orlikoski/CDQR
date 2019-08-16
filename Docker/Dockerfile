# Use the official Docker Hub Ubuntu 18.04 base image
FROM ubuntu:18.04
MAINTAINER @aorlikoski

ENV DEBIAN_FRONTEND noninteractive

# Setup install environment, Plaso, and Timesketch dependencies
RUN apt-get -qq -y update && \
    apt-get -qq -y --no-install-recommends install \
      software-properties-common \
      apt-transport-https && \
    add-apt-repository -u -y ppa:gift/stable && \
    apt-get -qq -y update && \
    apt-get -qq -y --assume-yes --no-install-recommends install \
      python-setuptools \
      curl \
      git \
      gpg-agent \
      libffi-dev \
      lsb-release \
      python3-dev \
      python3-setuptools \
      python-plaso \
      plaso-tools \
      python3 \
      python3-pip \
      python3-psycopg2 \
      python3-wheel && \
    curl -sS https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add - && \
    VERSION=node_8.x && \
    DISTRO="$(lsb_release -s -c)" && \
    echo "deb https://deb.nodesource.com/$VERSION $DISTRO main" > /etc/apt/sources.list.d/nodesource.list && \
    curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add - && \
    echo "deb https://dl.yarnpkg.com/debian/ stable main" > /etc/apt/sources.list.d/yarn.list && \
    apt-get -qq -y update && \
    apt-get -qq -y --no-install-recommends install \
      nodejs \
      yarn && \
    apt-get -y dist-upgrade && \
    apt-get -qq -y clean && \
    apt-get -qq -y autoclean && \
    apt-get -qq -y autoremove && \
    rm -rf /var/cache/apt/ /var/lib/apt/lists/

# Build and Install Timesketch from GitHub Master with Pip
RUN git clone https://github.com/google/timesketch.git /tmp/timesketch && \
    cd /tmp/timesketch && \
    git checkout d8c3ac17abdbf06d23614e0b68cff3bb94224c35 && \
    cd /tmp/timesketch && ls && yarn install && \
    yarn run build  && \
    pip3 install /tmp/timesketch/ && \
    pip3 install /tmp/timesketch/ && \
    sed -i -e '/pyyaml/d' /tmp/timesketch/requirements.txt && \
    rm -rf /tmp/*

# Download and install CDQR
RUN curl -s -o /usr/local/bin/cdqr.py \
      https://raw.githubusercontent.com/orlikoski/CDQR/master/src/cdqr.py && \
    chmod 755 /usr/local/bin/cdqr.py

# Load the entrypoint script to be run later
ENTRYPOINT ["/usr/local/bin/cdqr.py"]
