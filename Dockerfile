FROM ubuntu:trusty

RUN apt-get update
RUN apt-get install -y g++ gcc make libp11-kit-dev libgeoip-dev libyaml-cpp-dev libldap-dev libopendbx1-dev libopendbx1-sqlite3 libzmq3-dev libsqliteodbc bind9utils ldnsutils libnet-dns-perl moreutils unbound-host validns default-jre jq wget \
  libboost-all-dev \
  liblua5.1-dev \
  libedit-dev \
  libprotobuf-dev \
  pandoc\
  protobuf-compiler\
  libssl-dev \
  libmysqlclient-dev \
  libpq-dev \
  libkrb5-dev \
  libcurl4-openssl-dev \
  curl \
  libcdb-dev \
  unixodbc-dev \
  libsqlite3-dev\
  bison \
  autoconf \
  flex \
  ragel \
  sqlite3 \
  bc \
  dnsutils

RUN cd /tmp; \
    wget http://ppa.launchpad.net/kalon33/gamesgiroll/ubuntu/pool/main/libs/libsodium/libsodium-dev_1.0.3-1~ppa14.04+1_amd64.deb \
         http://ppa.launchpad.net/kalon33/gamesgiroll/ubuntu/pool/main/libs/libsodium/libsodium13_1.0.3-1~ppa14.04+1_amd64.deb; \
    dpkg -i libsodium-dev_1.0.3-1~ppa14.04+1_amd64.deb libsodium13_1.0.3-1~ppa14.04+1_amd64.deb
