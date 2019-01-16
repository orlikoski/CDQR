# Use the official Docker Hub Ubuntu 16.04 base image
FROM ubuntu:16.04

# Update the base image
RUN apt-get update && apt-get -y dist-upgrade && apt-get -y install software-properties-common wget

# Install Plaso
RUN add-apt-repository ppa:gift/stable
RUN apt-get update && apt-get -y install \
  python-plaso \
  plaso-tools \
  psycopg2 \
  python-pip

# Use pip to install Timesketch
RUN pip install pip==9.0.3 --no-cache-dir
RUN pip install timesketch

# Download and install latest version of CDQR
RUN wget -O /usr/local/bin/cdqr.py https://raw.githubusercontent.com/orlikoski/CDQR/master/src/cdqr.py
RUN chmod a+x /usr/local/bin/cdqr.py

# Load the entrypoint script to be run later
ENTRYPOINT ["/usr/local/bin/cdqr.py"]
