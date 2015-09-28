#
# Switchboard Controller Dockerfile
#

# Pull base image.
FROM dockerfile/python

# Install dependencies and application support.
RUN pip install cffi==1.2.1
RUN pip install pyOpenSSL==0.15.1
RUN pip install paramiko==1.15.2
RUN pip install urllib3==1.11
RUN pip install requests==2.7.0
RUN pip install ndg-httpsclient==0.4.0
RUN pip install lxml==3.4.4
RUN pip install supervisor==3.1.3 --pre

# Sigh.
# More dependencies, but these are badly specified and we have to work around conflicts.
RUN pip install pbr==1.6.0
RUN pip install oslo.config==2.3.0
RUN pip install pbr==0.10.8

# Finally, install Ryu...
RUN pip install ryu==3.25

# FIXME: Do controller installation here - probably a wget/untar/setup.py

# Define ports
EXPOSE 6633 8080
# FIXME: Ensure we have the right executable here.
CMD ["/usr/bin/supervisord"]
