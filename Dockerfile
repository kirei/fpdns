FROM perl:5.26.0

RUN apt-get update \
 && apt-get -y install libidn11-dev \
 && cpan install Net::DNS \
 && apt-get -y purge libidn11-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src
RUN perl Makefile.PL && make test && make install
