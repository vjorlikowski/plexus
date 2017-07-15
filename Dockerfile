#
# Plexus SDN Controller Dockerfile
#

# Pull base image.
FROM pypy:2

# Grab latest version of plexus, unpack it, install dependencies, and install it.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      wget \
      unzip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    wget -O /opt/plexus.zip "https://github.com/vjorlikowski/plexus/archive/master.zip" --no-check-certificate && \
    unzip -q /opt/plexus.zip -d /opt && \
    mv /opt/plexus-master /opt/plexus && \
    rm /opt/plexus.zip && \
    cd /opt/plexus && \
    pip install -r pip-requires && \
    pypy ./setup.py install

# Add the plexus user and group
RUN useradd -ms /sbin/nologin plexus

# Change ownership of the log directory
RUN chown -R plexus:plexus /var/log/plexus

# Define ports
EXPOSE 6633 8080

# Change user, and run.
USER plexus
ENTRYPOINT pypy /usr/local/bin/ryu run --config-file /etc/plexus/ryu.conf
