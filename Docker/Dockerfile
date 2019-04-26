# Use the official Docker Hub Ubuntu 18.04 base image
FROM ubuntu:18.04

# Update the base image
RUN apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade

# Setup install environment and Timesketch dependencies
RUN apt-get -y install apt-transport-https \
    curl \
    git \
    libffi-dev \
    lsb-release \
    python-dev \
    python-pip \
    python-psycopg2

RUN curl -sS https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add -
RUN VERSION=node_8.x && \
    DISTRO="$(lsb_release -s -c)" && \
    echo "deb https://deb.nodesource.com/$VERSION $DISTRO main" > /etc/apt/sources.list.d/nodesource.list
RUN curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
RUN echo "deb https://dl.yarnpkg.com/debian/ stable main" > /etc/apt/sources.list.d/yarn.list

# Install Plaso
RUN apt-get -y install software-properties-common
RUN add-apt-repository ppa:gift/stable && apt-get update
RUN apt-get update && apt-get -y install python-plaso=20190331-2ppa1~bionic plaso-tools=20190331-2ppa1~bionic nodejs yarn

# Build and Install Timesketch from GitHub Master with Pip
RUN git clone https://github.com/google/timesketch.git /tmp/timesketch
RUN cd /tmp/timesketch && git checkout tags/20190207 && yarn install && yarn run build
# Remove pyyaml from requirements.txt to avoid conflits with python-yaml ubuntu package
RUN sed -i -e '/pyyaml/d' /tmp/timesketch/requirements.txt
RUN pip install /tmp/timesketch/

# Download and install CDQR
RUN git clone https://github.com/orlikoski/CDQR.git /tmp/CDQR
RUN cd /tmp/CDQR && git checkout tags/5.0
RUN cp /tmp/CDQR/src/cdqr.py /usr/local/bin/cdqr.py
RUN chmod a+x /usr/local/bin/cdqr.py

# Cleanup apt cache
RUN apt-get -y autoremove --purge && apt-get -y clean && apt-get -y autoclean

# Load the entrypoint script to be run later
ENTRYPOINT ["/usr/local/bin/cdqr.py"]
