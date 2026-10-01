# This Dockerfile contains two images, `builder` and `runtime`.
# `builder` contains all necessary code to build
# `runtime` is stripped down.

ARG SOURCE_DATE_EPOCH
FROM debian:bookworm-slim AS builder

WORKDIR /

ENV COWRIE_GROUP=cowrie \
    COWRIE_USER=cowrie \
    COWRIE_HOME=/cowrie

ENV LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8

RUN groupadd -r ${COWRIE_GROUP} && \
    useradd -r -d ${COWRIE_HOME} -m -g ${COWRIE_GROUP} ${COWRIE_USER}

RUN export DEBIAN_FRONTEND=noninteractive; \
    apt-get -qq update && \
    apt-get -qq install -y \
        -o APT::Install-Suggests=false \
        -o APT::Install-Recommends=false \
        -o Dpkg::Use-Pty="0" \
      build-essential \
      ca-certificates \
      cargo \
      libffi-dev \
      libsnappy-dev \
      libssl-dev \
      python3 \
      python3-dev \
      python3-pip \
      python3-venv \
      rustc && \
    rm -rf /var/lib/apt/lists/*

USER ${COWRIE_USER}
WORKDIR ${COWRIE_HOME}

RUN mkdir -p ${COWRIE_HOME}/cowrie-git
COPY --chown=${COWRIE_USER}:${COWRIE_GROUP} requirements.txt requirements-output.txt ${COWRIE_HOME}/cowrie-git/

RUN python3 -m venv cowrie-env && \
    . cowrie-env/bin/activate && \
    pip install -q --no-cache-dir --upgrade pip setuptools wheel && \
    pip install -q --no-cache-dir --upgrade cffi && \
    pip install -q --no-cache-dir --upgrade -r ${COWRIE_HOME}/cowrie-git/requirements.txt && \
    pip install -q --no-cache-dir --upgrade -r ${COWRIE_HOME}/cowrie-git/requirements-output.txt

COPY --chown=${COWRIE_USER}:${COWRIE_GROUP} . ${COWRIE_HOME}/cowrie-git

RUN . cowrie-env/bin/activate && \
    SETUPTOOLS_SCM_PRETEND_VERSION=2.5.0 pip install ${COWRIE_HOME}/cowrie-git

# Add fake IoT filesystem files
COPY --chown=${COWRIE_USER}:${COWRIE_GROUP} setup_fakefs.sh ${COWRIE_HOME}/
COPY --chown=${COWRIE_USER}:${COWRIE_GROUP} update_fspickle.py ${COWRIE_HOME}/
RUN sh ${COWRIE_HOME}/setup_fakefs.sh && python3 ${COWRIE_HOME}/update_fspickle.py

FROM gcr.io/distroless/python3-debian12:latest AS runtime

LABEL org.opencontainers.image.authors="Michel Oosterhof <michel@oosterhof.net>"
LABEL org.opencontainers.image.url="https://cowrie.org/"
LABEL org.opencontainers.image.documentation="https://docs.cowrie.org"
LABEL org.opencontainers.image.source="https://github.com/cowrie/cowrie"
LABEL org.opencontainers.image.revision="Source control revision identifier for the packaged software."
LABEL org.opencontainers.image.vendor="Cowrie"
LABEL org.opencontainers.image.licenses="BSD-3-Clause"
LABEL org.opencontainers.image.title="Cowrie SSH/Telnet Honeypot"
LABEL org.opencontainers.image.description="Cowrie SSH/Telnet Honeypot"
LABEL org.opencontainers.image.base.name="gcr.io/distroless/python3-debian12"

ENV COWRIE_GROUP=cowrie \
    COWRIE_USER=cowrie \
    COWRIE_HOME=/cowrie

COPY --from=builder --chown=0:0 /etc/passwd /etc/group /etc/
COPY --from=builder --chown=${COWRIE_USER}:${COWRIE_GROUP} ${COWRIE_HOME} ${COWRIE_HOME}

RUN [ "python3", "-m", "compileall", "-q", "/cowrie/cowrie-git/src", "/cowrie/cowrie-env/", "/usr/lib/python3.11"]

VOLUME [ "/cowrie/cowrie-git/var", "/cowrie/cowrie-git/etc" ]

USER ${COWRIE_USER}
WORKDIR ${COWRIE_HOME}/cowrie-git

ENV PATH=${COWRIE_HOME}/cowrie-env/bin:${PATH}
ENV PYTHONPATH=${COWRIE_HOME}/cowrie-git/src
ENV PYTHONUNBUFFERED=1

RUN [ "python3", "/cowrie/cowrie-git/bin/regen-dropin.cache" ]

ENTRYPOINT [ "/cowrie/cowrie-env/bin/python3" ]
CMD [ "/cowrie/cowrie-env/bin/twistd", "-n", "--umask=0022", "--pidfile=", "cowrie" ]

EXPOSE 2222 2223
