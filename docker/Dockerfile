FROM ubuntu:24.04

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-dev \
        python3-venv \
        python3-pip \
        libcurl4-openssl-dev \
        libmysqlclient-dev \
        libsctp-dev \
        lksctp-tools \
        build-essential \
        pkg-config \
        libffi-dev \
        libssl-dev \
        libxml2-dev \
        libxslt-dev \
        libyaml-dev \
        git \
        default-libmysqlclient-dev \
        mysql-server \
        lksctp-tools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED

# Create and activate virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

#Create users on MySQL
RUN service mysql start && \
    #mysql -e "CREATE DATABASE IF NOT EXISTS hss;" && \
    mysql -e "CREATE USER 'dbeaver'@'localhost' IDENTIFIED BY 'password';" && \
    mysql -e "GRANT ALL PRIVILEGES ON hss.* TO 'dbeaver'@'localhost';" && \
    mysql -e "FLUSH PRIVILEGES;" 

# Bypass PEP 668 protection (like sudo pip install)
RUN echo "[global]\nbreak-system-packages = true" > /etc/pip.conf

# Clone repo
RUN git clone https://github.com/nickvsnetworking/pyhss.git
#Checkout to the latest commit
WORKDIR /pyhss
RUN git checkout DockerFixes

RUN pip install --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r /pyhss/requirements.txt

WORKDIR /pyhss/services

# Expose ports
EXPOSE 8080
EXPOSE 3868

ENTRYPOINT ["sh", "-c", "python apiService.py & python hssService.py & python diameterService.py & wait"]
