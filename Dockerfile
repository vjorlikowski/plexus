#
# Plexus SDN Controller Dockerfile
#

# Pull base image.
FROM python:2

# Grab latest version of plexus, unpack it, install dependencies, and install it.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      python-pip \
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
    python ./setup.py install

# Make the run directory
RUN mkdir -p /var/lib/plexus && \
    mkdir -p /var/run/plexus

# Add the plexus user and group
RUN useradd -ms /sbin/nologin plexus

RUN chown -R plexus:plexus /var/lib/plexus && \
    chown -R plexus:plexus /var/run/plexus && \
    chown -R plexus:plexus /var/log/plexus

# FIXME: need to make sure executable is in path, to avoid this hackery.
RUN sed -i -e 's%/opt/plexus%/usr/local%g' /etc/plexus/supervisord.conf

# FIXME: supervisord needs to run in the foreground.
RUN sed -i -e 's%nodaemon=false%nodaemon=true%g' /etc/plexus/supervisord.conf

# Define ports
EXPOSE 6633 8080
ENTRYPOINT /usr/local/bin/supervisord -c /etc/plexus/supervisord.conf
