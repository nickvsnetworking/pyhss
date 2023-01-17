FROM ubuntu:focal as builder
ENV DEBIAN_FRONTEND=noninteractive
ENV LD_LIBRARY_PATH=/open5gs/install/lib/x86_64-linux-gnu
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3-pip python3-dev\
        python3-setuptools \
        python3-wheel \
        ninja-build \
        build-essential \
        flex \
        bison \
        git \
        libsctp-dev \
        libgnutls28-dev \
        libgcrypt-dev \
        libssl-dev \
        libidn11-dev \
        libmongoc-dev \
        libbson-dev \
        libyaml-dev \
        meson \
        mongodb \
        curl \
        gnupg \
        ca-certificates \
        libmicrohttpd-dev \
        libcurl4-gnutls-dev \
        libnghttp2-dev \
        libtins-dev \
        libidn11-dev \
        libtalloc-dev \
        libpq-dev \
        libmysqlclient-dev \
        libsystemd-dev \
        python3-psycopg2 \
        vim \
        tcpdump \
        redis-server
RUN git clone https://github.com/nickvsnetworking/pyhss.git
WORKDIR pyhss
COPY config.yaml ./
COPY *.sh ./
RUN mkdir -p log && \
    pip3 install -r requirements.txt && \
    cp /pyhss/tools/Diameter_client.py /pyhss/ && \
    chmod +x *.sh

ENTRYPOINT [ "/pyhss/entrypoint.sh" ]
CMD [ "/usr/bin/python3", "hss.py" ] 
