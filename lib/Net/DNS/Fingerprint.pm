# $Id: Fingerprint.pm,v 1.17 2005/09/05 13:33:36 jakob Exp $
#
# Copyright (c) 2011 Verisign, Inc.
# Copyright (c) 2003,2004,2005 Roy Arends & Jakob Schlyter.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the authors may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package Net::DNS::Fingerprint;

use strict;
use warnings;
use Net::DNS;

our $VERSION = "0.10.0";

my %default = (
    source   => undef,
    timeout  => 5,
    retry    => 1,
    forcetcp => 0,
    debug    => 0,
    qversion => 0,
    qchaos   => 0,
);

my $versionlength = 40;

my $ignore_recurse = 0;

my @qy = (
    "0,QUERY,0,0,0,0,0,0,NOERROR,0,0,0,0",          #qy0
    "0,QUERY,0,0,0,1,0,1,NOERROR,0,0,0,0",          #qy1
    "0,NS_NOTIFY_OP,0,1,1,0,1,1,NOTIMP,0,0,0,0",    #qy2
    "0,IQUERY,0,0,0,1,1,1,NOERROR,0,0,0,0",         #qy3
    "0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",          #qy4
    "0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",          #qy5
    "0,IQUERY,0,1,1,0,0,0,NOTIMP,0,0,0,0",          #qy6
    "0,QUERY,0,0,0,0,0,1,NOTIMP,0,0,0,0",           #qy7
    "0,UPDATE,0,0,1,0,0,0,NOERROR,0,0,0,0",         #qy8
    "0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",          #qy9
    "0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",          #qy10
    "0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",          #qy11
);

my @nct = (
    ". IN A",                                       #nct0
    ". IN A",                                       #nct1
    ". IN A",                                       #nct2
    ". IN A",                                       #nct3
    "jjjjjjjjjjjj. CH A",                           #nct4
    "jjjjjjjjjjjj. CH RRSIG",                       #nct5
    ". IN A",                                       #nct6
    ". IN A",                                       #nct7
    ". IN A",                                       #nct8
    ". IN DNSKEY",                                  #nct9
    "jjjjjjjjjjjj. ANY TKEY",                       #nct10
    ". IN IXFR",                                    #nct11
);

my %initrule = (header => $qy[0], query => $nct[0],);
my @iq = (
    "1,QUERY,0,0,0,0,0,0,SERVFAIL,1,0,0,0",           #iq0
    "1,QUERY,0,0,0,0,0,0,NXDOMAIN,1,0,0,0",           #iq1
    "1,QUERY,0,0,0,0,0,0,NOERROR,1,0,0,0",            #iq2
    "1,QUERY,0,0,0,1,0,0,NOERROR,.+,.+,.+,.+",        #iq3
    "1,NS_NOTIFY_OP,0,0,1,1,0,1,FORMERR,1,0,0,0",     #iq4
    "1,NS_NOTIFY_OP,0,0,1,1,0,0,FORMERR,1,0,0,0",     #iq5
    "1,NS_NOTIFY_OP,0,0,1,1,0,0,REFUSED,1,0,0,0",     #iq6
    "0,NS_NOTIFY_OP,0,1,1,0,1,1,NOTIMP,1,0,0,0",      #iq7
    "1,IQUERY,0,0,0,1,0,0,NOTIMP,1,0,0,0",            #iq8
    "0,IQUERY,0,0,0,1,1,1,NOERROR,1,0,0,0",           #iq9
    "1,QUERY,0,0,1,0,0,0,NOTIMP,1,0,0,0",             #iq10
    "0,QUERY,0,0,1,0,0,0,NOERROR,1,0,0,0",            #iq11
    "1,NS_NOTIFY_OP,0,0,1,1,0,0,SERVFAIL,1,0,0,0",    #iq12
    "1,IQUERY,0,0,1,1,0,0,SERVFAIL,1,0,0,0",          #iq13
    "1,IQUERY,0,0,1,1,0,0,NOTIMP,0,0,0,0",            #iq14
    "1,QUERY,0,0,0,1,0,0,NOTIMP,.+,.+,.+,.+",         #iq15
    "1,QUERY,0,0,0,1,0,1,NOERROR,.+,.+,.+,.+",        #iq16
    "1,UPDATE,0,0,1,1,0,0,FORMERR,1,0,0,0",           #iq17
    "1,QUERY,0,0,1,0,0,0,SERVFAIL,1,0,0,0",           #iq18
    "1,QUERY,0,0,1,0,0,0,REFUSED,1,0,0,0",            #iq19
    "1,UPDATE,0,0,1,1,0,0,FORMERR,0,0,0,0",           #iq20
    "1,QUERY,0,0,1,1,0,0,NOERROR,.+,.+,.+,.+",        #iq21
    "1,QUERY,0,1,1,1,0,0,NOERROR,.+,.+,.+,.+",        #iq22
    "1,QUERY,0,0,0,0,0,0,REFUSED,0,0,0,0",            #iq23
    "1,QUERY,0,0,1,1,0,0,REFUSED,1,0,0,0",            #iq24
    "1,QUERY,0,0,1,1,0,0,NXDOMAIN,.+,.+,.+,.+",       #iq25
);

my @ruleset = (
    {
        fingerprint => $iq[0],
        result      => {
            vendor  => "NLnetLabs",
            product => "NSD",
            version => "3.1.0 -- 3.2.8"
        },
    },
    {
        fingerprint => $iq[1],
        result =>
          { vendor => "Unlogic", product => "Eagle DNS", version => "1.1.1" },
    },
    {
        fingerprint => $iq[2],
        result      => {
            vendor  => "Unlogic",
            product => "Eagle DNS",
            version => "1.0 -- 1.0.1"
        },
    },
    {
        fingerprint => $iq[3],
        header      => $qy[1],
        query       => $nct[1],
        ruleset     => [
            {
                fingerprint => $iq[3],
                header      => $qy[2],
                query       => $nct[2],
                ruleset     => [
                    {
                        fingerprint => $iq[4],
                        result      => {
                            vendor  => "ISC",
                            product => "BIND",
                            version => "9.3.0 -- 9.3.6-P1"
                        },
                    },
                    {
                        fingerprint => $iq[5],
                        result      => {
                            vendor  => "ISC",
                            product => "BIND",
                            version => "9.2.3 -- 9.2.9"
                        },
                    },
                    {
                        fingerprint => $iq[6],
                        result      => {
                            vendor  => "ISC",
                            product => "BIND",
                            version => "9.1.1 -- 9.1.3"
                        },
                    },
                    {
                        fingerprint => "query timed out",
                        header      => $qy[3],
                        query       => $nct[3],
                        ruleset     => [
                            {
                                fingerprint => $iq[8],
                                result      => {
                                    vendor  => "Microsoft",
                                    product => "Windows DNS",
                                    version => "2003"
                                },
                            },
                            {
                                fingerprint => "query timed out",
                                header      => $qy[4],
                                query       => $nct[4],
                                ruleset     => [
                                    {
                                        fingerprint => $iq[10],
                                        result      => {
                                            vendor  => "Microsoft",
                                            product => "Windows DNS",
                                            version => "2003 R2"
                                        },
                                    },
                                    {
                                        fingerprint => "query timed out",
                                        header      => $qy[5],
                                        query       => $nct[5],
                                        ruleset     => [
                                            {
                                                fingerprint =>
                                                  "query timed out",
                                                result => {
                                                    vendor  => "Microsoft",
                                                    product => "Windows DNS",
                                                    version => "2008 R2"
                                                },
                                            },
                                            {
                                                fingerprint => $iq[10],
                                                result      => {
                                                    vendor  => "Microsoft",
                                                    product => "Windows DNS",
                                                    version => "2008"
                                                },
                                            },
                                            {
                                                fingerprint => ".+",
                                                state =>
                                                  "q0r3q1r3q2r7q3r9q4r11q5r?"
                                            },
                                        ]
                                    },
                                ]
                            },
                        ]
                    },
                    {
                        fingerprint => $iq[12],
                        header      => $qy[6],
                        query       => $nct[6],
                        ruleset     => [
                            {
                                fingerprint => $iq[13],
                                result      => {
                                    vendor  => "",
                                    product => "Google DNS",
                                    version => ""
                                },
                            },
                            {
                                fingerprint => $iq[14],
                                header      => $qy[7],
                                query       => $nct[7],
                                ruleset     => [
                                    {
                                        fingerprint => $iq[15],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version => "9.2.0rc3"
                                        },
                                    },
                                    {
                                        fingerprint => $iq[3],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version => "9.2.0 -- 9.2.2-P3"
                                        },
                                    },
                                    {
                                        fingerprint => ".+",
                                        state => "q0r3q1r3q2r7r12q6r14q7r?"
                                    },
                                ]
                            },
                        ]
                    },
                ]
            },
            {
                fingerprint => $iq[16],
                header      => $qy[2],
                query       => $nct[2],
                ruleset     => [
                    {
                        fingerprint => "query timed out",
                        result      => {
                            vendor  => "Microsoft",
                            product => "Windows DNS",
                            version => "2000"
                        },
                    },
                    {
                        fingerprint => $iq[4],
                        header      => $qy[8],
                        query       => $nct[8],
                        ruleset     => [
                            {
                                fingerprint => $iq[17],
                                header      => $qy[4],
                                query       => $nct[4],
                                ruleset     => [
                                    {
                                        fingerprint => $iq[18],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version => "9.7.2"
                                        },
                                    },
                                    {
                                        fingerprint => $iq[19],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version => "9.6.3 -- 9.7.3"
                                        },
                                    },
                                    {
                                        fingerprint => ".+",
                                        state => "q0r3q1r3r16q2r4q8r17q4r?"
                                    },
                                ]
                            },
                            {
                                fingerprint => $iq[20],
                                header      => $qy[4],
                                query       => $nct[4],
                                ruleset     => [
                                    {
                                        fingerprint => $iq[19],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version => "9.5.2 -- 9.7.1"
                                        },
                                    },
                                    {
                                        fingerprint => $iq[18],
                                        header      => $qy[9],
                                        query       => $nct[9],
                                        ruleset     => [
                                            {
                                                fingerprint => $iq[21],
                                                result      => {
                                                    vendor  => "ISC",
                                                    product => "BIND",
                                                    version =>
                                                      "9.6.0 OR 9.4.0 -- 9.5.1"
                                                },
                                            },
                                            {
                                                fingerprint => $iq[22],
                                                result      => {
                                                    vendor  => "ISC",
                                                    product => "BIND",
                                                    version => "9.4.0 -- 9.5.1"
                                                },
                                            },
                                            {
                                                fingerprint => ".+",
                                                state =>
"q0r3q1r3r16q2r4q8r17r20q4r18q9r?"
                                            },
                                        ]
                                    },
                                ]
                            },
                        ]
                    },
                ]
            },
        ]
    },
    {
        fingerprint => $iq[23],
        header      => $qy[10],
        query       => $nct[10],
        ruleset     => [
            {
                fingerprint => $iq[24],
                result      => {
                    vendor  => "NLnetLabs",
                    product => "Unbound",
                    version => "1.3.0 -- 1.4.0"
                },
            },
            {
                fingerprint => $iq[25],
                header      => $qy[11],
                query       => $nct[11],
                ruleset     => [
                    {
                        fingerprint => "header section incomplete",
                        result      => {
                            vendor  => "NLnetLabs",
                            product => "Unbound",
                            version => "1.4.1 -- 1.4.9"
                        },
                    },
                    {
                        fingerprint => $iq[19],
                        result      => {
                            vendor  => "NLnetLabs",
                            product => "Unbound",
                            version => "1.4.10 -- 1.4.12"
                        },
                    },
                    { fingerprint => ".+", state => "q0r3r23q10r25q11r?" },
                ]
            },
        ]
    },
);

my @qy_old = (
    "0,IQUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",
    "0,NS_NOTIFY_OP,0,0,0,0,0,0,NOERROR,0,0,0,0",
    "0,QUERY,0,0,0,0,0,0,NOERROR,0,0,0,0",
    "0,IQUERY,0,0,0,0,1,1,NOERROR,0,0,0,0",
    "0,QUERY,0,0,0,0,0,0,NOTIMP,0,0,0,0",
    "0,IQUERY,1,0,1,1,1,1,NOERROR,0,0,0,0",
    "0,UPDATE,0,0,0,1,0,0,NOERROR,0,0,0,0",
    "0,QUERY,1,1,1,1,1,1,NOERROR,0,0,0,0",
    "0,QUERY,0,0,0,0,0,1,NOERROR,0,0,0,0",
);

my %old_initrule = (header => $qy_old[2], query => ". IN MAILB",);

my @iq_old = (
    "1,IQUERY,0,0,1,0,0,0,FORMERR,0,0,0,0",    # iq_old0
    "1,IQUERY,0,0,1,0,0,0,FORMERR,1,0,0,0",    # iq_old1
    "1,IQUERY,0,0,1,0,0,0,NOTIMP,0,0,0,0",     # iq_old2
    "1,IQUERY,0,0,1,0,0,0,NOTIMP,1,0,0,0",     # iq_old3
    "1,IQUERY,0,0,1,1,0,0,FORMERR,0,0,0,0",    # iq_old4
    "1,IQUERY,0,0,1,1,0,0,NOTIMP,0,0,0,0",     # iq_old5
    "1,IQUERY,0,0,1,1,0,0,NOTIMP,1,0,0,0",     # iq_old6
    "1,IQUERY,1,0,1,0,0,0,NOTIMP,1,0,0,0",     # iq_old7
    "1,QUERY,1,0,1,0,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,0,0,0,0,0,0,NOTIMP,0,0,0,0",
    "1,IQUERY,0,0,1,1,0,0,FORMERR,1,0,0,0",    # iq_old10
    "1,NS_NOTIFY_OP,0,0,0,0,0,0,FORMERR,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,0,0,0,NOTIMP,0,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,0,0,0,NOTIMP,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,0,0,0,NXDOMAIN,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,0,0,0,REFUSED,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,0,0,0,SERVFAIL,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,1,0,0,FORMERR,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,1,0,0,NOTIMP,0,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,1,0,0,NOTIMP,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,1,0,0,REFUSED,1,0,0,0",    # iq_old20
    "1,NS_NOTIFY_OP,0,0,0,1,0,0,SERVFAIL,1,0,0,0",
    "1,NS_NOTIFY_OP,1,0,0,0,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,1,0,0,0,0,0,NOTIMP,1,0,0,0",
    "1,NS_NOTIFY_OP,1,0,0,0,0,0,SERVFAIL,1,0,0,0",
    "1,IQUERY,0,0,0,0,1,1,NOTIMP,0,0,0,0",
    "1,IQUERY,0,0,0,0,0,0,NOTIMP,0,0,0,0",
    "1,IQUERY,0,0,1,1,1,1,FORMERR,0,0,0,0",
    "1,IQUERY,1,0,1,1,1,1,FORMERR,0,0,0,0",
    "1,QUERY,.,0,1,.,.,.,NOTIMP,.+,.+,.+,.+",
    "1,QUERY,.,0,1,.,.,.,.+,.+,.+,.+,.+",            #iq_old30
    "1,QUERY,0,0,.,.,0,0,NXDOMAIN,1,0,0,0",
    "1,QUERY,0,0,.,.,0,0,FORMERR,1,0,0,0",
    "1,UPDATE,0,0,0,0,0,0,NOTIMP,0,0,0,0",
    "1,UPDATE,0,0,0,1,0,0,NOTIMP,0,0,0,0",
    "1,QUERY,0,0,1,0,0,0,NOERROR,1,0,0,0",
    "1,QUERY,1,1,1,1,1,1,NOTIMP,1,0,0,0",
    "1,QUERY,0,0,0,0,0,0,NOERROR,1,0,.+,0",
    "1,QUERY,0,0,1,0,0,0,FORMERR,1,0,0,0",
    "1,IQUERY,0,0,1,0,1,1,NOTIMP,1,0,0,0",
    "1,IQUERY,0,0,0,1,1,1,REFUSED,1,0,0,0",          #iq_old40
    "1,UPDATE,0,0,0,1,0,0,REFUSED,1,0,0,0",
    "1,IQUERY,0,0,0,1,1,1,FORMERR,0,0,0,0",
    "1,IQUERY,0,0,0,1,0,0,NOTIMP,0,0,0,0",
    "1,QUERY,1,0,1,0,0,0,FORMERR,1,0,0,0",
    "1,UPDATE,0,0,0,0,0,0,FORMERR,1,0,0,0",
    "1,UPDATE,0,0,0,0,0,0,FORMERR,0,0,0,0",
    "1,QUERY,0,0,1,0,0,0,FORMERR,0,0,0,0",
    "1,QUERY,0,0,1,0,0,0,SERVFAIL,1,0,0,0",          #iq_old48
    "1,QUERY,1,0,1,0,0,0,NXDOMAIN,1,0,1,0",
    "1,QUERY,0,0,1,0,0,0,REFUSED,1,0,0,0",           #iq_old50
    "1,QUERY,0,0,1,0,0,0,NOERROR,1,1,0,0",
    "1,IQUERY,0,0,1,0,0,0,REFUSED,0,0,0,0",
    "1,QUERY,0,0,0,0,0,0,FORMERR,0,0,0,0",
    "1,QUERY,0,0,1,1,1,0,NOERROR,1,0,1,0",
    "1,QUERY,0,0,1,1,0,0,NOERROR,1,0,1,0",
    "1,QUERY,0,0,1,0,1,0,NOERROR,.+,.+,.+,.+",
    "1,QUERY,0,0,1,0,0,0,.+,.+,.+,.+,.+",
    "1,QUERY,1,0,1,0,0,0,NOERROR,1,1,0,0",
    "1,QUERY,0,0,1,1,0,0,SERVFAIL,1,0,0,0",
    "1,QUERY,1,0,1,1,0,0,NOERROR,1,1,0,0",           #iq_old60
    "1,QUERY,0,0,1,1,0,0,REFUSED,1,0,0,0",
    "1,QUERY,0,0,0,0,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,1,0,1,1,0,0,NOERROR,1,0,1,0",
    "1,IQUERY,0,0,1,1,1,1,NOTIMP,0,0,0,0",
    "1,UPDATE,0,0,0,0,0,0,REFUSED,0,0,0,0",
    "1,IQUERY,0,0,0,1,1,1,NOTIMP,1,0,0,0",
    "1,IQUERY,0,0,0,1,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,0,1,1,1,1,1,NOERROR,1,0,.,0",
    "1,QUERY,0,1,1,1,0,1,NOERROR,1,0,.,0",
    "1,IQUERY,0,0,1,0,0,0,REFUSED,1,0,0,0",          #iq_old70
    "1,IQUERY,1,0,1,1,1,1,NOTIMP,1,0,0,0",
    "1,IQUERY,0,0,1,0,0,0,NOERROR,1,0,0,0",
    "1,QUERY,1,0,1,1,0,0,NOERROR,1,0,0,0",
    "1,IQUERY,1,0,1,1,0,0,NXDOMAIN,1,0,0,0",
    "1,UPDATE,0,0,0,1,0,0,FORMERR,0,0,0,0",
    "1,IQUERY,1,0,1,0,0,0,NXDOMAIN,1,0,0,0",
    "1,QUERY,0,0,1,1,0,0,FORMERR,1,0,0,0",
    "1,QUERY,0,0,0,1,0,0,SERVFAIL,1,0,0,0",
    "1,QUERY,0,0,1,1,0,0,NOERROR,1,1,0,0",
    "1,IQUERY,1,0,1,0,0,0,NOERROR,1,0,1,0",          #iq_old80
    "1,IQUERY,1,0,1,1,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,0,0,1,1,0,0,NOERROR,1,0,0,0",
    "1,QUERY,1,0,1,1,0,0,NOERROR,1,1,1,.+",
    "1,QUERY,0,0,1,1,0,0,REFUSED,0,0,0,0",
    "1,UPDATE,0,0,0,1,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,1,0,0,1,0,0,NXDOMAIN,1,0,0,0",
    "1,QUERY,0,0,0,1,0,0,NOTIMP,0,0,0,0",
    "1,QUERY,0,0,0,0,0,0,REFUSED,1,0,0,0",
    "1,QUERY,1,0,1,1,0,0,NXDOMAIN,1,0,0,0",          #iq_old89
    "1,QUERY,1,0,0,0,0,0,NOERROR,1,1,0,0",           #iq_old90
    "1,IQUERY,1,0,1,1,0,1,NOTIMP,1,0,0,0",
    "1,QUERY,0,0,0,1,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,0,0,1,0,0,1,SERVFAIL,1,0,0,0",
    "1,QUERY,0,0,0,1,0,0,NOERROR,1,0,13,13",         #iq_old94
    "1,QUERY,0,0,0,1,0,0,NOERROR,1,0,1,0",           #iq_old95
    "1,QUERY,0,0,1,0,0,0,NOERROR,1,0,13,13",
    "1,IQUERY,1,0,0,0,0,0,NOTIMP,1,0,0,0",           #iq_old97
    "1,IQUERY,1,0,0,0,1,1,NOTIMP,1,0,0,0",           #iq_old98
    "1,IQUERY,0,0,1,1,0,0,NOERROR,1,0,1,0",          #iq_old99
    "1,QUERY,.,0,1,0,0,0,NOERROR,1,0,0,0",           #iq_old100
    "1,QUERY,0,0,1,0,0,0,NXDOMAIN,1,0,0,0",          #101
);

my @old_ruleset = (
    {
        fingerprint => $iq_old[89],
        result      => {
            vendor  => "Simon Kelley",
            product => "dnsmasq",
            version => ""
        },
        qv => "version.bind",
    },
    {
        fingerprint => ".+",
        header      => $qy_old[0],
        query       => ". IN A",
        ruleset     => [
            {
                fingerprint => "query timed out",
                header      => $qy_old[0],
                query       => "com. IN A",
                ruleset     => [
                    {
                        fingerprint => "query timed out",
                        header      => $qy_old[7],
                        query       => ". CH A",
                        ruleset     => [
                            {
                                fingerprint => "query timed out",
                                header      => $qy_old[6],
                                query       => ". IN A",
                                ruleset     => [
                                    {
                                        fingerprint => $iq_old[38],
                                        result      => {
                                            vendor  => "Digital Lumber",
                                            product => "Oak DNS",
                                            version => ""
                                        },
                                        qv => "version.oak",
                                    },
                                    {
                                        fingerprint => "query timed out",
                                        result      => "TIMEOUT",
                                    },
                                    {
                                        fingerprint => ".+",
                                        state       => "q0tq0tq7tq6r?",
                                    },
                                ]
                            },
                            {
                                fingerprint => $iq_old[35],
                                result      => {
                                    vendor  => "XBILL",
                                    product => "jnamed (dnsjava)",
                                    version => ""
                                },
                            },
                            {
                                fingerprint => $iq_old[36],
                                result      => {
                                    vendor  => "Men & Mice",
                                    product => "QuickDNS for MacOS Classic",
                                    version => ""
                                },
                            },
                            {
                                fingerprint => $iq_old[37],
                                result      => {
                                    vendor  => "unknown",
                                    product => "NonSequitur DNS",
                                    version => ""
                                },
                            },
                            { fingerprint => ".+", state => "q0tq0tq7r?", },
                        ]
                    },
                    {
                        fingerprint => $iq_old[35],
                        result      => {
                            vendor  => "eNom",
                            product => "eNom DNS",
                            version => ""
                        },
                    },
                    { fingerprint => ".+", state => "q0tq0r?", },
                ]
            },

            {
                fingerprint => $iq_old[0],
                header      => $qy_old[1],
                query       => "jjjjjjjjjjjj IN A",
                ruleset     => [
                    {
                        fingerprint => $iq_old[12],
                        result      => {
                            vendor  => "ISC",
                            product => "BIND",
                            version => "8.4.1-p1"
                        },
                        qv => "version.bind",
                    },
                    {
                        fingerprint => $iq_old[13],
                        result      => {
                            vendor  => "ISC",
                            product => "BIND",
                            version => "8 plus root server modifications"
                        },
                        qv => "version.bind",
                    },
                    {
                        fingerprint => $iq_old[15],
                        result      => {
                            vendor  => "Cisco",
                            product => "CNR",
                            version => ""
                        },
                    },
                    {
                        fingerprint => $iq_old[16],
                        header      => $qy_old[2],
                        query       => "hostname.bind CH TXT",
                        ruleset     => [
                            {
                                fingerprint => $iq_old[58],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version => "8.3.0-RC1 -- 8.4.4"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[50],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version => "8.3.0-RC1 -- 8.4.4"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[48],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version => "8.2.2-P3 -- 8.3.0-T2A"
                                },
                                qv => "version.bind",
                            },
                            { fingerprint => ".+", state => "q0r0q1r16q2r?", },
                        ]
                    },
                    { fingerprint => ".+", state => "q0r0q1r?", },
                ]
            },

            {
                fingerprint => $iq_old[1],
                header      => $qy_old[2],
                query       => ". IN IXFR",
                ruleset     => [
                    {
                        fingerprint => $iq_old[31],
                        result      => {
                            vendor  => "Microsoft",
                            product => "Windows DNS",
                            version => "2000"
                        },
                    },
                    {
                        fingerprint => $iq_old[32],
                        result      => {
                            vendor  => "Microsoft",
                            product => "Windows DNS",
                            version => "NT4"
                        },
                    },
                    {
                        fingerprint => $iq_old[50],
                        result      => {
                            vendor  => "Microsoft",
                            product => "Windows DNS",
                            version => "2003"
                        },
                    },
                    { fingerprint => ".+", state => "q0r1q2r?", },
                ]
            },

            {
                fingerprint => $iq_old[2],
                header      => $qy_old[1],
                ruleset     => [
                    {
                        fingerprint => $iq_old[11],
                        result      => {
                            vendor  => "ISC",
                            product => "BIND",
                            version => "9.2.3rc1 -- 9.4.0a4"
                        },
                        qv => "version.bind",
                    },
                    {
                        fingerprint => $iq_old[12],
                        header      => $qy_old[3],
                        ruleset     => [
                            {
                                fingerprint => $iq_old[25],
                                header      => $qy_old[6],
                                ruleset     => [
                                    {
                                        fingerprint => $iq_old[33],
                                        result      => {
                                            vendor  => "bboy",
                                            product => "MyDNS",
                                            version => ""
                                        },
                                    },
                                    {
                                        fingerprint => $iq_old[34],
                                        header      => $qy_old[2],
                                        query =>
"012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.0123456789012345678901234567890123456789012345678901234567890. IN A",
                                        ruleset => [
                                            {
                                                fingerprint => $iq_old[47],
                                                result      => {
                                                    vendor  => "NLnetLabs",
                                                    product => "NSD",
                                                    version => "1.0.3 -- 1.2.1"
                                                },
                                                qv => "version.server",
                                            },
                                            {
                                                fingerprint => $iq_old[48],
                                                header      => $qy_old[2],
                                                query => "hostname.bind CH TXT",
                                                ruleset => [
                                                    {
                                                        fingerprint =>
                                                          $iq_old[50],
                                                        result => {
                                                            vendor =>
                                                              "NLnetLabs",
                                                            product => "NSD",
                                                            version => "1.2.2"
                                                        },
                                                        qv => "version.server",
                                                    },
                                                    {
                                                        fingerprint =>
                                                          $iq_old[51],
                                                        header  => $qy_old[8],
                                                        query   => ". IN A",
                                                        ruleset => [
                                                            {
                                                                fingerprint =>
                                                                  $iq_old[93],
                                                                result => {
                                                                    vendor =>
"NLnetLabs",
                                                                    product =>
                                                                      "NSD",
                                                                    version =>
"1.2.3 -- 2.1.2"
                                                                },
                                                                qv =>
"version.server",
                                                            },
                                                            {
                                                                fingerprint =>
                                                                  $iq_old[48],
                                                                result => {
                                                                    vendor =>
"NLnetLabs",
                                                                    product =>
                                                                      "NSD",
                                                                    version =>
                                                                      "2.1.3"
                                                                },
                                                                qv =>
"version.server",
                                                            },
                                                            {
                                                                fingerprint =>
                                                                  ".+",
                                                                state =>
"q0r2q1r12q3r25q6r34q2r48q2r51q8r?",
                                                            },
                                                        ]
                                                    },
                                                    {
                                                        fingerprint => ".+",
                                                        state =>
"q0r2q1r12q3r25q6r34q2r48q2r?",
                                                    },
                                                ]
                                            },
                                            {
                                                fingerprint => $iq_old[49],
                                                header      => $qy_old[2],
                                                query => "hostname.bind CH TXT",
                                                ruleset => [
                                                    {
                                                        fingerprint =>
                                                          $iq_old[50],
                                                        result => {
                                                            vendor =>
                                                              "NLnetLabs",
                                                            product => "NSD",
                                                            version =>
                                                              "1.2.2 [root]"
                                                        },
                                                        qv => "version.server",
                                                    },
                                                    {
                                                        fingerprint =>
                                                          $iq_old[51],
                                                        result => {
                                                            vendor =>
                                                              "NLnetLabs",
                                                            product => "NSD",
                                                            version =>
                                                              "1.2.3 [root]"
                                                        },
                                                        qv => "version.server",
                                                    },
                                                    {
                                                        fingerprint => ".+",
                                                        state =>
"q0r2q1r12q3r25q6r34q2r49q2r?",
                                                    },
                                                ]
                                            },
                                            {
                                                fingerprint => $iq_old[53],
                                                result      => {
                                                    vendor  => "NLnetLabs",
                                                    product => "NSD",
                                                    version => "1.0.2"
                                                },
                                                qv => "version.server",
                                            },
                                            {
                                                fingerprint => ".+",
                                                state =>
                                                  "q0r2q1r12q3r25q6r34q2a?",
                                            },
                                        ]
                                    },
                                    {
                                        fingerprint => ".+",
                                        state       => "q0r2q1r12q3r25q6r?",
                                    },
                                ]
                            },
                            {
                                fingerprint => $iq_old[26],
                                result      => {
                                    vendor  => "VeriSign",
                                    product => "ATLAS",
                                    version => ""
                                },
                            },
                            { fingerprint => ".+", state => "q0r2q1r12q3r?", },
                        ]
                    },
                    {
                        fingerprint => $iq_old[15],
                        header      => $qy_old[6],
                        ruleset     => [
                            {
                                fingerprint => $iq_old[45],
                                result      => {
                                    vendor  => "Nominum",
                                    product => "ANS",
                                    version => ""
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[65],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version => "9.2.3rc1 -- 9.4.0a4"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[46],
                                header      => $qy_old[7],
                                ruleset     => [
                                    {
                                        fingerprint => $iq_old[56],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version => "9.0.0b5 -- 9.0.1"
                                        },
                                        qv => "version.bind",
                                    },
                                    {
                                        fingerprint => $iq_old[57],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version => "9.1.0 -- 9.1.3"
                                        },
                                        qv => "version.bind",
                                    },
                                    {
                                        fingerprint => ".+",
                                        state       => "q0r2q1r15q6r46q7r?",
                                    },
                                ]
                            },
                            { fingerprint => ".+", state => "q0r2q1r15q6r?", },
                        ]
                    },
                    {
                        fingerprint => $iq_old[16],
                        header      => $qy_old[4],
                        ruleset     => [
                            {
                                fingerprint => $iq_old[29],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version => "9.2.0a1 -- 9.2.0rc3"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[30],
                                header      => $qy_old[0],
                                query       => ". A CLASS0",
                                ruleset     => [
                                    {
                                        fingerprint => $iq_old[2],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version => "9.2.0rc7 -- 9.2.2-P3"
                                        },
                                        qv => "version.bind",
                                    },
                                    {
                                        fingerprint => $iq_old[0],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version => "9.2.0rc4 -- 9.2.0rc6"
                                        },
                                        qv => "version.bind",
                                    },
                                    {
                                        fingerprint => ".+",
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version => "9.2.0rc4 -- 9.2.2-P3"
                                        },
                                        qv => "version.bind",
                                    },
                                ]
                            },
                            { fingerprint => ".+", state => "q0r2q1r16q4r?", },
                        ]
                    },
                    { fingerprint => ".+", state => "q0r2q1r?", },
                ]
            },

            {
                fingerprint => $iq_old[3],
                header      => $qy_old[1],
                ruleset     => [
                    {
                        fingerprint => "query timed out",
                        header      => $qy_old[5],
                        ruleset     => [
                            {
                                fingerprint => $iq_old[3],
                                result      => {
                                    vendor  => "sourceforge",
                                    product => "Dents",
                                    version => ""
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[81],
                                result      => {
                                    vendor  => "Microsoft",
                                    product => "Windows DNS",
                                    version => "2003"
                                },
                            },
                            {
                                fingerprint => $iq_old[91],
                                result      => {
                                    vendor  => "Microsoft",
                                    product => "Windows DNS",
                                    version => "2003"
                                },
                            },
                            { fingerprint => ".+", state => "q0r3q1tq5r?", },
                          ]

                    },
                    {
                        fingerprint => $iq_old[14],
                        result      => {
                            vendor  => "UltraDNS",
                            product => "",
                            version => "v2.7.0.2 -- 2.7.3"
                        },
                        qv => "version.bind",
                    },
                    {
                        fingerprint => $iq_old[13],
                        header      => $qy_old[5],
                        ruleset     => [
                            {
                                fingerprint => $iq_old[39],
                                result      => {
                                    vendor  => "pliant",
                                    product => "DNS Server",
                                    version => ""
                                },
                            },
                            {
                                fingerprint => $iq_old[7],
                                result      => {
                                    vendor  => "JHSOFT",
                                    product => "simple DNS plus",
                                    version => ""
                                },
                            },
                            {
                                fingerprint => $iq_old[71],
                                header      => $qy_old[6],
                                ruleset     => [
                                    {
                                        fingerprint => $iq_old[41],
                                        result      => {
                                            vendor  => "Netnumber",
                                            product => "ENUM server",
                                            version => ""
                                        },
                                    },
                                    {
                                        fingerprint => $iq_old[85],
                                        result      => {
                                            vendor  => "Raiden",
                                            product => "DNSD",
                                            version => ""
                                        },
                                    },
                                ]
                            },
                            { fingerprint => ".+", state => "q0r3q1r13q5r?", },
                        ]
                    },
                    { fingerprint => ".+", state => "q0r3q1r?", },
                ]
            },

            {
                fingerprint => $iq_old[4],
                header      => $qy_old[1],
                query       => "jjjjjjjjjjjj IN A",
                ruleset     => [
                    {
                        fingerprint => $iq_old[17],
                        result      => {
                            vendor  => "ISC",
                            product => "BIND",
                            version => "9.0.0b5 -- 9.0.1 [recursion enabled]"
                        },
                        qv => "version.bind",
                    },
                    {
                        fingerprint => $iq_old[18],
                        header      => $qy_old[5],
                        query       => ". IN A",
                        ruleset     => [
                            {
                                fingerprint => $iq_old[27],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version => "4.9.3 -- 4.9.11"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[28],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version => "4.8 -- 4.8.3"
                                },
                            },
                            { fingerprint => ".+", state => "q0r4q1r18q5r?", },
                        ]
                    },
                    {
                        fingerprint => $iq_old[19],
                        result      => {
                            vendor  => "ISC",
                            product => "BIND",
                            version => "8.2.1 [recursion enabled]"
                        },
                        qv => "version.bind",
                    },
                    {
                        fingerprint => $iq_old[20],
                        header      => $qy_old[3],
                        query       => ". IN A",
                        ruleset     => [
                            {
                                fingerprint => $iq_old[42],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version =>
                                      "8.1-REL -- 8.2.1-T4B [recursion enabled]"
                                },
                                qv => "version.bind",
                            },
                            { fingerprint => ".+", state => "q0r4q1r20q3r?", },
                        ]
                    },
                    {
                        fingerprint => $iq_old[21],
                        header      => $qy_old[2],
                        query       => "hostname.bind CH TXT",
                        ruleset     => [
                            {
                                fingerprint => $iq_old[60],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version =>
                                      "8.3.0-RC1 -- 8.4.4 [recursion enabled]"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[59],
                                header      => $qy_old[7],
                                query       => ". IN A",
                                ruleset     => [
                                    {
                                        fingerprint => $iq_old[68],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version =>
"8.1-REL -- 8.2.1-T4B [recursion enabled]"
                                        },
                                        qv => "version.bind",
                                    },
                                    {
                                        fingerprint => $iq_old[69],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version =>
"8.2.2-P3 -- 8.3.0-T2A [recursion enabled]"
                                        },
                                        qv => "version.bind",
                                    },
                                    {
                                        fingerprint => "connection failed",
                                        result      => {
                                            vendor  => "Runtop",
                                            product => "dsl/cable",
                                            version => ""
                                        },
                                    },
                                    {
                                        fingerprint => ".+",
                                        state       => "q0r4q1r21q2r59q7r?",
                                    },
                                ]
                            },

                            {
                                fingerprint => $iq_old[58],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version =>
                                      "8.3.0-RC1 -- 8.4.4 [recursion local]"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[50],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version =>
                                      "8.3.0-RC1 -- 8.4.4 [recursion local]"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[61],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version =>
                                      "8.3.0-RC1 -- 8.4.4 [recursion local]"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[48],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version =>
                                      "8.2.2-P3 -- 8.3.0-T2A [recursion local]"
                                },
                                qv => "version.bind",
                            },
                            { fingerprint => ".+", state => "q0r4q1r21q2r?", },
                        ]
                    },
                    { fingerprint => ".+", state => "q0r4q1r?", },
                ]
            },

            {
                fingerprint => $iq_old[5],
                header      => $qy_old[1],
                ruleset     => [
                    {
                        fingerprint => $iq_old[11],
                        result      => {
                            vendor  => "ISC",
                            product => "BIND",
                            version => "9.2.3rc1 -- 9.4.0a4",
                            option  => "recursion enabled,split view"
                        },
                        qv => "version.bind",
                    },
                    {
                        fingerprint => $iq_old[17],
                        result      => {
                            vendor  => "ISC",
                            product => "BIND",
                            version => "9.2.3rc1 -- 9.4.0a4 [recursion enabled]"
                        },
                        qv => "version.bind",
                    },
                    {
                        fingerprint => $iq_old[18],
                        header      => $qy_old[5],
                        ruleset     => [
                            {
                                fingerprint => $iq_old[5],
                                header      => $qy_old[7],
                                query       => ". IN A",
                                ruleset     => [
                                    {
                                        fingerprint => $iq_old[84],
                                        result      => {
                                            vendor  => "Nominum",
                                            product => "CNS",
                                            version => ""
                                        },
                                        qv => "version.bind",
                                    },
                                    {
                                        fingerprint => $iq_old[59],
                                        result      => {
                                            vendor  => "Mikrotik",
                                            product => "dsl/cable",
                                            version => ""
                                        },
                                    },
                                    {
                                        fingerprint => $iq_old[82],
                                        result      => {
                                            vendor  => "Mikrotik",
                                            product => "dsl/cable",
                                            version => ""
                                        },
                                    },
                                    {
                                        fingerprint => ".+",
                                        state       => "q0r5q1r18q5r5q7r?",
                                    },
                                ]
                            },
                            {
                                fingerprint => $iq_old[64],
                                result => "unknown, smells like old BIND 4",
                            },
                            { fingerprint => ".+", state => "q0r5q1r18q5r?", },
                        ]
                    },
                    {
                        fingerprint => $iq_old[20],
                        header      => $qy_old[7],
                        ruleset     => [
                            {
                                fingerprint => $iq_old[54],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version =>
                                      "9.0.0b5 -- 9.0.1 [recursion enabled]"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[55],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version =>
                                      "9.1.0 -- 9.1.3 [recursion enabled]"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[63],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version =>
                                      "4.9.3 -- 4.9.11 [recursion enabled]"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[61],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version =>
                                      "9.0.0b5 -- 9.1.3 [recursion local]"
                                },
                                qv => "version.bind",
                            },
                            { fingerprint => ".+", state => "q0r5q1r20q7r?", },
                        ]
                    },
                    {
                        fingerprint => $iq_old[21],
                        header      => $qy_old[4],
                        ruleset     => [
                            {
                                fingerprint => "query timed out",
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version =>
                                      "9.2.0a1 -- 9.2.2-P3 [recursion enabled]"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[29],
                                result      => {
                                    vendor  => "ISC",
                                    product => "BIND",
                                    version =>
                                      "9.2.0a1 -- 9.2.0rc3 [recursion enabled]"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[61],
                                header      => $qy_old[0],
                                query       => ". A CLASS0",
                                ruleset     => [
                                    {
                                        fingerprint => $iq_old[2],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version =>
"9.2.0rc7 -- 9.2.2-P3 [recursion local]"
                                        },
                                        qv => "version.bind",
                                    },
                                    {
                                        fingerprint => $iq_old[0],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version =>
"9.2.0a1 -- 9.2.0rc6 [recursion local]"
                                        },
                                        qv => "version.bind",
                                    },
                                    {
                                        fingerprint => ".+",
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version =>
"9.2.0a1 -- 9.2.2-P3 [recursion local]"
                                        },
                                        qv => "version.bind",
                                    },
                                ]
                            },
                            {
                                fingerprint => $iq_old[30],
                                header      => $qy_old[0],
                                query       => ". A CLASS0",
                                ruleset     => [
                                    {
                                        fingerprint => $iq_old[2],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version =>
"9.2.0rc7 -- 9.2.2-P3 [recursion enabled]"
                                        },
                                        qv => "version.bind",
                                    },
                                    {
                                        fingerprint => $iq_old[0],
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version =>
"9.2.0rc4 -- 9.2.0rc6 [recursion enabled]"
                                        },
                                        qv => "version.bind",
                                    },
                                    {
                                        fingerprint => ".+",
                                        result      => {
                                            vendor  => "ISC",
                                            product => "BIND",
                                            version =>
"9.2.0rc4 -- 9.2.2-P3 [recursion enabled]"
                                        },
                                        qv => "version.bind",
                                    },
                                ]
                            },
                            { fingerprint => ".+", state => "q0r5q1r21q4r?", },
                        ]
                    },
                    { fingerprint => ".+", state => "q0r5q1r?", },
                ]
            },

            {
                fingerprint => $iq_old[6],
                header      => $qy_old[1],
                ruleset     => [
                    {
                        fingerprint => $iq_old[15],
                        result      => {
                            vendor  => "incognito",
                            product => "DNS commander",
                            version => "v2.3.1.1 -- 4.0.5.1"
                        },
                        qv => "version.bind",
                    },
                    {
                        fingerprint => $iq_old[19],
                        header      => $qy_old[3],
                        ruleset     => [
                            {
                                fingerprint => $iq_old[66],
                                result      => {
                                    vendor  => "vermicelli",
                                    product => "totd",
                                    version => ""
                                },
                            },
                            {
                                fingerprint => $iq_old[67],
                                result      => {
                                    vendor  => "JHSOFT",
                                    product => "simple DNS plus",
                                    version => "[recursion enabled]"
                                },
                            },
                            { fingerprint => ".+", state => "q0r6q1r19q3r?", },
                        ]
                    },
                    { fingerprint => ".+", state => "q0r6q1r?", },
                ]
            },

            {
                fingerprint => $iq_old[7],
                header      => $qy_old[1],
                ruleset     => [
                    {
                        fingerprint => $iq_old[22],
                        header      => $qy_old[3],
                        ruleset     => [
                            {
                                fingerprint => $iq_old[97],
                                result      => {
                                    vendor  => "PowerDNS",
                                    product => "PowerDNS",
                                    version => "2.9.4 -- 2.9.19"
                                },
                                qv => "version.bind",
                            },
                            {
                                fingerprint => $iq_old[98],
                                result      => {
                                    vendor  => "Stanford",
                                    product => "lbnamed",
                                    version => "1.0.0 -- 2.3.2"
                                },
                            },
                            { fingerprint => ".+", state => "q0r7q1r22q3r?", },
                        ]
                    },
                    {
                        fingerprint => $iq_old[24],
                        result      => {
                            vendor  => "PowerDNS",
                            product => "PowerDNS",
                            version => "2.8 -- 2.9.3"
                        },
                        qv => "version.bind",
                    },
                    { fingerprint => ".+", state => "q0r7q1r?", },
                ]
            },

            {
                fingerprint => $iq_old[8],
                header      => $qy_old[1],
                ruleset     => [
                    {
                        fingerprint => $iq_old[23],
                        header      => $qy_old[2],
                        query       => ". CH A",
                        ruleset     => [
                            {
                                fingerprint => "query timed out",
                                result      => {
                                    vendor  => "DJ Bernstein",
                                    product => "TinyDNS",
                                    version => "1.04"
                                },
                            },
                            {
                                fingerprint => $iq_old[32],
                                result      => {
                                    vendor  => "DJ Bernstein",
                                    product => "TinyDNS",
                                    version => "1.05"
                                },
                            },
                            { fingerprint => ".+", state => "q0r8q1r23q2r?", },
                        ]
                    },
                    { fingerprint => ".+", state => "q0r8q1r?", },
                ]
            },

            {
                fingerprint => $iq_old[9],
                header      => $qy_old[1],
                ruleset     => [
                    {
                        fingerprint => $iq_old[9],
                        result      => {
                            vendor  => "Sam Trenholme",
                            product => "MaraDNS",
                            version => ""
                        },
                        qv => "erre-con-erre-cigarro.maradns.org"
                    },
                    { fingerprint => ".+", state => "q0r9q1r?", },
                ]
            },

            {
                fingerprint => $iq_old[10],
                result      => {
                    vendor  => "Microsoft",
                    product => "?",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[26],
                result      => {
                    vendor  => "Meilof Veeningen",
                    product => "Posadis",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[43],
                header      => $qy_old[6],
                ruleset     => [
                    {
                        fingerprint => $iq_old[34],
                        result      => {
                            vendor  => "Paul Rombouts",
                            product => "pdnsd",
                            version => ""
                        },
                    },
                    {
                        fingerprint => $iq_old[75],
                        result      => {
                            vendor  => "antirez",
                            product => "Yaku-NS",
                            version => ""
                        },
                    },
                    { fingerprint => ".+", state => "q0r43q6r?", },
                ]
            },

            {
                fingerprint => $iq_old[44],
                result      => {
                    vendor  => "cpan",
                    product => "Net::DNS Nameserver",
                    version => ""
                },
                qv => "version.bind",
            },
            {
                fingerprint => $iq_old[52],
                result      => {
                    vendor  => "NLnetLabs",
                    product => "NSD",
                    version => "1.0 alpha"
                },
            },
            {
                fingerprint => $iq_old[55],
                header      => $qy_old[3],
                ruleset     => [
                    {
                        fingerprint => $iq_old[94],
                        result      => {
                            vendor  => "robtex",
                            product => "Viking DNS module",
                            version => ""
                        },
                    },
                    {
                        fingerprint => $iq_old[95],
                        result      => {
                            vendor  => "cisco",
                            product => "dns resolver/server",
                            version => ""
                        },
                    },
                    { fingerprint => ".+", state => "q0r55q3r?", },
                ]
            },
            {
                fingerprint => $iq_old[59],
                result      => {
                    vendor  => "Max Feoktistov",
                    product => "small HTTP server [recursion enabled]",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[60],
                result      => {
                    vendor  => "Axis",
                    product => "video server",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[62],
                header      => $qy_old[7],
                query       => "1.0.0.127.in-addr.arpa. IN PTR",
                ruleset     => [
                    {
                        fingerprint => $iq_old[62],
                        result      => {
                            vendor  => "Michael Tokarev",
                            product => "rbldnsd",
                            version => ""
                        },
                        qv => "version.bind",
                    },
                    {
                        fingerprint => $iq_old[79],
                        result      => {
                            vendor  => "4D",
                            product => "WebSTAR",
                            version => ""
                        },
                    },
                    {
                        fingerprint => $iq_old[83],
                        result      => {
                            vendor  => "Netopia",
                            product => "dsl/cable",
                            version => ""
                        },
                    },
                    {
                        fingerprint => $iq_old[90],
                        result      => {
                            vendor  => "TZO",
                            product => "Tzolkin DNS",
                            version => ""
                        },
                    },
                    {
                        fingerprint => "query timed out",
                        result      => {
                            vendor  => "Netopia",
                            product => "dsl/cable",
                            version => ""
                        },
                    },
                    { fingerprint => ".+", state => "q0r62q7r?", },
                ]
            },
            {
                fingerprint => $iq_old[70],
                result      => {
                    vendor  => "Yutaka Sato",
                    product => "DeleGate DNS",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[72],
                result      => {
                    vendor  => "",
                    product => "sheerdns",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[73],
                result      => {
                    vendor  => "Matthew Pratt",
                    product => "dproxy",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[74],
                result      => {
                    vendor  => "Brad Garcia",
                    product => "dnrd",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[76],
                result      => {
                    vendor  => "Sourceforge",
                    product => "JDNSS",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[77],
                result      => {
                    vendor  => "Dan Kaminsky",
                    product => "nomde DNS tunnel",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[78],
                result      => {
                    vendor  => "Max Feoktistov",
                    product => "small HTTP server",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[79],
                result      => {
                    vendor  => "robtex",
                    product => "Viking DNS module",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[80],
                result      => {
                    vendor  => "Fasthosts",
                    product => "Envisage DNS server",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[81],
                result      => {
                    vendor  => "WinGate",
                    product => "Wingate DNS",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[82],
                result      => {
                    vendor  => "Ascenvision",
                    product => "SwiftDNS",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[86],
                result      => {
                    vendor  => "Nortel Networks",
                    product => "Instant Internet",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[87],
                result      => {
                    vendor  => "ATOS",
                    product => "Stargate ADSL",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[88],
                result      => {
                    vendor  => "3Com",
                    product => "Office Connect Remote",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[89],
                result      => {
                    vendor  => "Alteon",
                    product => "ACEswitch",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[90],
                result      => {
                    vendor  => "javaprofessionals",
                    product => "javadns/jdns",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[92],
                result      => {
                    vendor  => "Beehive",
                    product => "CoDoNS",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[96],
                result      => {
                    vendor  => "Beevihe",
                    product => "AAAAAA",
                    version => ""
                },
                qv => "version.bind",
            },
            {
                fingerprint => $iq_old[100],
                result      => {
                    vendor  => "ValidStream",
                    product => "ValidDNS",
                    version => ""
                },
            },
            {
                fingerprint => $iq_old[101],
                result      => {
                    vendor  => "ValidStream",
                    product => "ValidDNS",
                    version => ""
                },
            },
            { fingerprint => ".+", state => "q0r?", },

        ]
    },

);

######################################################################

sub new {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self  = {};

    my %config = @_;

    foreach my $k (keys %default) {
        if (defined $config{$k}) {
            $self->{$k} = $config{$k};
        } else {
            $self->{$k} = $default{$k};
        }
    }

    bless $self, $class;
    return $self;
}

sub hash {
    my $self = shift;

    my $addr = shift;
    my $port = shift;

    $port = 53 unless ($port);

    return $self->init($addr, $port);
}

sub string {
    my $self = shift;

    my $addr = shift;
    my $port = shift;

    $port = 53 unless ($port);

    my %r = $self->hash($addr, $port);

    my @s = ();

    if (defined $r{error}) {
        push @s, $r{error};
    } elsif (defined $r{result}) {
        push @s, $r{result};
    } else {
        push @s, $r{vendor}     if (defined $r{vendor});
        push @s, $r{product}    if (defined $r{product});
        push @s, $r{version}    if (defined $r{version});
        push @s, "[$r{option}]" if (defined $r{option});
        push @s, "[$r{ruleset} Rules]" if (defined $r{ruleset});
    }

    push @s, $r{vstring} if (defined $r{vstring});

    push @s, $r{state} if (defined $r{state} && $self->{debug});

    return join(" ", @s);
}

sub query_version {
    my $self = shift;

    my $qserver = shift;
    my $qport   = shift;
    my $ident   = shift;

    my $rrset    = " id: ";
    my $resolver = Net::DNS::Resolver->new;

    $resolver->nameservers($qserver);
    $resolver->port($qport);
    $resolver->srcaddr($self->{source});
    $resolver->retry($self->{retry});
    $resolver->retrans($self->{timeout});
    $resolver->usevc($self->{forcetcp});
    my $query = $resolver->query($ident, 'TXT', 'CH');

    if ($query && $query->header->ancount > 0) {
        foreach my $rr ($query->answer) {
            ($rrset = $rrset . "\"" . $rr->txtdata . "\" ")
              if ($rr->type eq "TXT");
        }
        $rrset =~ s/\n/\" \"/g;
        if (length($rrset) > $versionlength) {
            $rrset = substr($rrset, 0, $versionlength) . "...";
        }
        return $rrset;
    }

    return " id unavailable (" . $resolver->errorstring . ")";
}

sub init {
    my $self = shift;

    my $qserver = shift;
    my $qport   = shift;

    my %match =
      $self->process($qserver,
	$qport,
	$initrule{header},
	$initrule{query},
        \@ruleset,
	"New");

    return %match if (defined $match{product});

    #For backwards compatibility with old fingerprint code which never set the rd
    $ignore_recurse = 1;
    return $self->process($qserver,
	$qport,
	$old_initrule{header},
        $old_initrule{query},
	\@old_ruleset,
	"Old");
}

sub process {
    my $self = shift;

    my $qserver = shift;
    my $qport   = shift;
    my $qheader = shift;
    my $qstring = shift;
    my $ruleref = shift;
    my $rulenam = shift;
    my $ver;
    my $id;
    my %ret;

    if ($self->{debug}) {
        print STDERR "==> PROCESS $qserver:$qport $qheader $qstring\n";
        print STDERR "\n";
    }

    my ($answer, $ress) = $self->probe($qserver, $qport, $qheader, $qstring);

    if ($answer) {
        $id = header2fp($answer->header);
    } else {
        $id = $ress;
    }

    print STDERR "==> \"$id\"\n" if ($self->{debug});

    for my $rule (@$ruleref) {

        $ver = " ";

        # we must have a fingerprint
        die "missing fingerprint" unless (defined $rule->{fingerprint});

        # skip to next rule unless we have a matching fingerprint
        next unless ($id =~ /$rule->{fingerprint}/);

        # return if we have a result
        if (defined $rule->{result}) {
            if (defined $rule->{qv}) {
                $ver = $self->query_version($qserver, $qport, $rule->{qv})
                  if $self->{qversion};
            }
            if ($self->{qchaos}) {
                $ver = $self->query_version($qserver, $qport, "version.bind");
            }
            $ret{vstring} = $ver if ($ver);

            if (ref($rule->{result})) {
                $ret{vendor}  = $rule->{result}{vendor};
                $ret{product} = $rule->{result}{product};
                $ret{version} = $rule->{result}{version};
                $ret{option}  = $rule->{result}{option};
                $ret{state}   = $rule->{result}{state};
		$ret{ruleset} = $rulenam;
            } else {
                $ret{result} = $rule->{result};
            }

            return %ret;
        }

        # print state if no matches
        if (defined $rule->{state}) {
            $ver = $self->query_version($qserver, $qport, "hostname.bind")
              if $self->{qversion};
            $ret{vstring} = $ver if ($ver);

            $ret{error} = "No match found";
            $ret{state} = $rule->{state};
            $ret{id}    = $id;

            return %ret;
        }

        # update query if defined
        if (defined $rule->{query}) {
            $qstring = $rule->{query};
        }

        # recurse if we have a new header and a new ruleset
        if (defined $rule->{header} && defined $rule->{ruleset}) {
            return $self->process(
                $qserver, $qport, $rule->{header},
                $qstring, $rule->{ruleset}, $rulenam
            );
        }

        die "syntax error";
    }

    return %ret;
}

sub header2fp {
    my $header = shift;

    my @list = (
        $header->qr,      $header->opcode,  $header->aa,
        $header->tc,      $header->rd,      $header->ra,
        $header->ad,      $header->cd,      $header->rcode,
        $header->qdcount, $header->ancount, $header->nscount,
        $header->arcount
    );

    return join(",", @list);
}

sub fp2header {
    my @list = split(/,/, shift);
    my $header = shift;

    $header->qr(shift @list);
    $header->opcode(shift @list);
    $header->aa(shift @list);
    $header->tc(shift @list);
    $header->rd(shift @list);
    $header->ra(shift @list);
    $header->ad(shift @list);
    $header->cd(shift @list);
    $header->rcode(shift @list);

    my ($qdcount, $ancount, $nscount, $arcount) = @list;
    $header->qdcount($qdcount) unless $qdcount == $header->qdcount;
    $header->qdcount($ancount) unless $ancount == $header->ancount;
    $header->qdcount($nscount) unless $nscount == $header->nscount;
    $header->qdcount($arcount) unless $arcount == $header->arcount;
}

sub probe {
    my $self = shift;

    my $qserver = shift;
    my $qport   = shift;
    my $qheader = shift;
    my @qstring = split(/ /, shift);

    my $packet = new Net::DNS::Packet;
    fp2header($qheader, $packet->header);
    $packet->push("question", Net::DNS::Question->new(@qstring));

    if ($self->{debug}) {
        print STDERR "==> QUERY BEGIN\n";
        print STDERR $packet->print, "\n";
        print STDERR "==> QUERY END\n";
        print STDERR "\n";
    }

    my $resolver = Net::DNS::Resolver->new;
    $resolver->nameservers($qserver);
    if (!$ignore_recurse) {
        $resolver->recurse($packet->header->rd);
    }
    $resolver->port($qport);
    $resolver->srcaddr($self->{source});
    $resolver->retry($self->{retry});
    $resolver->retrans($self->{timeout});
    $resolver->usevc($self->{forcetcp});
    my $answer = $resolver->send($packet);
    if ($answer && $self->{debug}) {
        print STDERR "==> ANSWER BEGIN\n";
        print STDERR $answer->string, "\n";
        print STDERR "==> ANSWER END\n";
        print STDERR "\n";
    }

    return ($answer, $resolver->errorstring);
}

sub version {
    return $VERSION;
}

1;
