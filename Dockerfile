# An incomplete base Docker image for running JupyterHub
#
# Add your configuration to create a complete derivative Docker image.
#
# Include your configuration settings by starting with one of two options:
#
# Option 1:
#
# FROM jupyterhub/jupyterhub:latest
#
# And put your configuration file jupyterhub_config.py in /srv/jupyterhub/jupyterhub_config.py.
#
# Option 2:
#
# Or you can create your jupyterhub config and database on the host machine, and mount it with:
#
# docker run -v $PWD:/srv/jupyterhub -t jupyterhub/jupyterhub
#
# NOTE
# If you base on jupyterhub/jupyterhub-onbuild
# your jupyterhub_config.py will be added automatically
# from your docker directory.

ARG BASE_IMAGE=ubuntu:20.04
FROM $BASE_IMAGE AS builder

USER root

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update \
 && apt-get install -yq --no-install-recommends \
    build-essential \
    ca-certificates \
    locales \
    python3-dev \
    python3-pip \
    python3-pycurl \
    nodejs \
    npm \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --upgrade setuptools pip wheel

# copy everything except whats in .dockerignore, its a
# compromise between needing to rebuild and maintaining
# what needs to be part of the build
COPY . /src/jupyterhub/
WORKDIR /src/jupyterhub

# Build client component packages (they will be copied into ./share and
# packaged with the built wheel.)
RUN python3 setup.py bdist_wheel
RUN python3 -m pip wheel --wheel-dir wheelhouse dist/*.whl


FROM $BASE_IMAGE

USER root

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -yq --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    locales \
    python3-pip \
    python3-pycurl \
    nodejs \
    npm \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

ENV SHELL=/bin/bash \
    LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8

RUN  locale-gen $LC_ALL

# always make sure pip is up to date!
RUN python3 -m pip install --no-cache --upgrade setuptools pip

RUN npm install -g configurable-http-proxy@^4.2.0 \
 && rm -rf ~/.npm

# install the wheels we built in the first stage
COPY --from=builder /src/jupyterhub/wheelhouse /tmp/wheelhouse
RUN python3 -m pip install --no-cache /tmp/wheelhouse/*

RUN mkdir -p /srv/jupyterhub/
WORKDIR /srv/jupyterhub/

EXPOSE 8000

LABEL maintainer="Jupyter Project <jupyter@googlegroups.com>"
LABEL org.jupyter.service="jupyterhub"

ARG CAI_USER="cai"

RUN apt-get update && \
    useradd -ms /bin/bash -d /srv/jupyterhub ${CAI_USER} && \
    apt-get install -y --no-install-recommends \
     build-essential \
     default-libmysqlclient-dev \
     git \
     vim \
     less \
     python-dev \
     python3-dev \
     python3-setuptools \
     python3-wheel \
     libcurl4-openssl-dev \
     libldap2-dev \
     libsasl2-dev \
     libssl-dev\
     dnsutils \
     && \
    rm -rf /var/lib/apt/lists/* && \
    chown -R ${CAI_USER}:${CAI_USER} /srv/jupyterhub

COPY --chown=${CAI_USER}:${CAI_USER} cai-custom-files/requirements.txt cai-custom-files/oauthenticator-14.2.0-py3-none-any.whl /tmp/
RUN PYCURL_SSL_LIBRARY=openssl pip3 install --no-cache-dir -r /tmp/requirements.txt
RUN pip3 install /tmp/oauthenticator-14.2.0-py3-none-any.whl

COPY --chown=${CAI_USER}:${CAI_USER} cai-custom-files/ldap.conf /home/jovyan/.configs/ldap.conf
COPY --chown=${CAI_USER}:${CAI_USER} cai-custom-files/utils /srv/jupyterhub/utils

### Copy the main configuration file
COPY --chown=${CAI_USER}:${CAI_USER} cai-custom-files/jupyterhub_config.py /srv/jupyterhub/jupyterhub_config.py
### Copy the logo inside the container
COPY --chown=${CAI_USER}:${CAI_USER} cai-custom-files/coutureai.png /srv/jupyterhub/coutureai.png

USER ${CAI_USER}

CMD ["jupyterhub", "--port=8888", "--log-level=0", "--debug", "--config", "/srv/jupyterhub/jupyterhub_config.py"]
