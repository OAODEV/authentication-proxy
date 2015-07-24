# Start with a base container of ubuntu 14.04 when this project is
# built it will download the base ubuntu image and apply all changes
# to that.
FROM ubuntu:14.04

# This simply identifies the maintainer of the container
MAINTAINER matt.urban@adops.com

# each `RUN` statement applies a change to the container by executing
# the command in the container. Here we first update the package manager
# Then install a few external dependencies (python, pip, git and the
# mock library).
RUN sudo apt-get update
RUN sudo apt-get install -y python python-pip python-dev python2.7-dev

ADD ./requirements.txt /app/requirements.txt

# Run all commands from this folder. This is where the service will be
# located after the last step copies the files in.

WORKDIR /app

RUN pip install -r requirements.txt

ADD . /app

RUN touch /var/secrets
ADD Manifest /Manifest

# Launch service
CMD python authentication_proxy.py