FROM perl:5.26.0

RUN apt-get update \
 && apt-get install libidn11-dev \
 && rm -rf /var/lib/apt/lists/*
RUN cpan install Net::DNS

COPY . /src
WORKDIR /src
RUN perl Makefile.PL && make test && make install
