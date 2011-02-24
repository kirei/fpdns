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

require 5.6.0;

package Net::DNS::Fingerprint;

use strict;
use warnings;
use Net::DNS 0.42;

our $VERSION = "0.9.4-current";

my %default = (
    source   => undef,
    timeout  => 5,
    retry    => 1,
    forcetcp => 0,
    debug    => 0,
    qversion => 0,
    qchaos   => 0,
    separator => " ",
);

my $versionlength = 40;

my @qy = ("0,IQUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",
          "0,NS_NOTIFY_OP,0,0,0,0,0,0,NOERROR,0,0,0,0",
          "0,QUERY,0,0,0,0,0,0,NOERROR,0,0,0,0",
          "0,IQUERY,0,0,0,0,1,1,NOERROR,0,0,0,0",
          "0,QUERY,0,0,0,0,0,0,NOTIMP,0,0,0,0",
          "0,IQUERY,1,0,1,1,1,1,NOERROR,0,0,0,0",
          "0,UPDATE,0,0,0,1,0,0,NOERROR,0,0,0,0",
          "0,QUERY,1,1,1,1,1,1,NOERROR,0,0,0,0", 
          "0,QUERY,0,0,0,0,0,1,NOERROR,0,0,0,0",
         );

my %initrule = (header => $qy[2], query  => ". IN MAILB", );
# my %initrule = (header => $qy[0], query  => ". IN A", );
my @iq = ("1,IQUERY,0,0,1,0,0,0,FORMERR,0,0,0,0",   # iq0
          "1,IQUERY,0,0,1,0,0,0,FORMERR,1,0,0,0",   # iq1
          "1,IQUERY,0,0,1,0,0,0,NOTIMP,0,0,0,0",    # iq2
          "1,IQUERY,0,0,1,0,0,0,NOTIMP,1,0,0,0",    # iq3
          "1,IQUERY,0,0,1,1,0,0,FORMERR,0,0,0,0",   # iq4
          "1,IQUERY,0,0,1,1,0,0,NOTIMP,0,0,0,0",    # iq5 
          "1,IQUERY,0,0,1,1,0,0,NOTIMP,1,0,0,0",    # iq6
          "1,IQUERY,1,0,1,0,0,0,NOTIMP,1,0,0,0",    # iq7
          "1,QUERY,1,0,1,0,0,0,NOTIMP,1,0,0,0",
          "1,QUERY,0,0,0,0,0,0,NOTIMP,0,0,0,0",
          "1,IQUERY,0,0,1,1,0,0,FORMERR,1,0,0,0",   # iq10
	  "1,NS_NOTIFY_OP,0,0,0,0,0,0,FORMERR,1,0,0,0",
          "1,NS_NOTIFY_OP,0,0,0,0,0,0,NOTIMP,0,0,0,0",
          "1,NS_NOTIFY_OP,0,0,0,0,0,0,NOTIMP,1,0,0,0",
          "1,NS_NOTIFY_OP,0,0,0,0,0,0,NXDOMAIN,1,0,0,0",
          "1,NS_NOTIFY_OP,0,0,0,0,0,0,REFUSED,1,0,0,0",
          "1,NS_NOTIFY_OP,0,0,0,0,0,0,SERVFAIL,1,0,0,0",
          "1,NS_NOTIFY_OP,0,0,0,1,0,0,FORMERR,1,0,0,0",
          "1,NS_NOTIFY_OP,0,0,0,1,0,0,NOTIMP,0,0,0,0",
          "1,NS_NOTIFY_OP,0,0,0,1,0,0,NOTIMP,1,0,0,0",
          "1,NS_NOTIFY_OP,0,0,0,1,0,0,REFUSED,1,0,0,0", # iq20
          "1,NS_NOTIFY_OP,0,0,0,1,0,0,SERVFAIL,1,0,0,0",
          "1,NS_NOTIFY_OP,1,0,0,0,0,0,NOTIMP,1,0,0,0",
          "1,QUERY,1,0,0,0,0,0,NOTIMP,1,0,0,0",
          "1,NS_NOTIFY_OP,1,0,0,0,0,0,SERVFAIL,1,0,0,0",
	  "1,IQUERY,0,0,0,0,1,1,NOTIMP,0,0,0,0",
          "1,IQUERY,0,0,0,0,0,0,NOTIMP,0,0,0,0",
          "1,IQUERY,0,0,1,1,1,1,FORMERR,0,0,0,0",
          "1,IQUERY,1,0,1,1,1,1,FORMERR,0,0,0,0",
	  "1,QUERY,.,0,1,.,.,.,NOTIMP,.+,.+,.+,.+",
          "1,QUERY,.,0,1,.,.,.,.+,.+,.+,.+,.+", #iq30
          "1,QUERY,0,0,.,.,0,0,NXDOMAIN,1,0,0,0",    
	  "1,QUERY,0,0,.,.,0,0,FORMERR,1,0,0,0",
          "1,UPDATE,0,0,0,0,0,0,NOTIMP,0,0,0,0",
          "1,UPDATE,0,0,0,1,0,0,NOTIMP,0,0,0,0",
          "1,QUERY,0,0,1,0,0,0,NOERROR,1,0,0,0",
          "1,QUERY,1,1,1,1,1,1,NOTIMP,1,0,0,0",
          "1,QUERY,0,0,0,0,0,0,NOERROR,1,0,.+,0",
          "1,QUERY,0,0,1,0,0,0,FORMERR,1,0,0,0",
          "1,IQUERY,0,0,1,0,1,1,NOTIMP,1,0,0,0",
          "1,IQUERY,0,0,0,1,1,1,REFUSED,1,0,0,0", #iq40
          "1,UPDATE,0,0,0,1,0,0,REFUSED,1,0,0,0",
          "1,IQUERY,0,0,0,1,1,1,FORMERR,0,0,0,0",
          "1,IQUERY,0,0,0,1,0,0,NOTIMP,0,0,0,0",
          "1,QUERY,1,0,1,0,0,0,FORMERR,1,0,0,0",
          "1,UPDATE,0,0,0,0,0,0,FORMERR,1,0,0,0",
          "1,UPDATE,0,0,0,0,0,0,FORMERR,0,0,0,0",
          "1,QUERY,0,0,1,0,0,0,FORMERR,0,0,0,0",
          "1,QUERY,0,0,1,0,0,0,SERVFAIL,1,0,0,0", #iq48
          "1,QUERY,1,0,1,0,0,0,NXDOMAIN,1,0,1,0",
          "1,QUERY,0,0,1,0,0,0,REFUSED,1,0,0,0", #iq50
          "1,QUERY,0,0,1,0,0,0,NOERROR,1,1,0,0",
          "1,IQUERY,0,0,1,0,0,0,REFUSED,0,0,0,0",
          "1,QUERY,0,0,0,0,0,0,FORMERR,0,0,0,0",
          "1,QUERY,0,0,1,1,1,0,NOERROR,1,0,1,0",
          "1,QUERY,0,0,1,1,0,0,NOERROR,1,0,1,0",
          "1,QUERY,0,0,1,0,1,0,NOERROR,.+,.+,.+,.+", 
          "1,QUERY,0,0,1,0,0,0,.+,.+,.+,.+,.+",
          "1,QUERY,1,0,1,0,0,0,NOERROR,1,1,0,0",
          "1,QUERY,0,0,1,1,0,0,SERVFAIL,1,0,0,0", 
          "1,QUERY,1,0,1,1,0,0,NOERROR,1,1,0,0", #iq60
          "1,QUERY,0,0,1,1,0,0,REFUSED,1,0,0,0",
          "1,QUERY,0,0,0,0,0,0,NOTIMP,1,0,0,0",
          "1,QUERY,1,0,1,1,0,0,NOERROR,1,0,1,0",
	  "1,IQUERY,0,0,1,1,1,1,NOTIMP,0,0,0,0",
          "1,UPDATE,0,0,0,0,0,0,REFUSED,0,0,0,0",
          "1,IQUERY,0,0,0,1,1,1,NOTIMP,1,0,0,0",
          "1,IQUERY,0,0,0,1,0,0,NOTIMP,1,0,0,0",
          "1,QUERY,0,1,1,1,1,1,NOERROR,1,0,.,0",
          "1,QUERY,0,1,1,1,0,1,NOERROR,1,0,.,0",
          "1,IQUERY,0,0,1,0,0,0,REFUSED,1,0,0,0", #iq70
          "1,IQUERY,1,0,1,1,1,1,NOTIMP,1,0,0,0",
          "1,IQUERY,0,0,1,0,0,0,NOERROR,1,0,0,0",
	  "1,QUERY,1,0,1,1,0,0,NOERROR,1,0,0,0",
          "1,IQUERY,1,0,1,1,0,0,NXDOMAIN,1,0,0,0",
          "1,UPDATE,0,0,0,1,0,0,FORMERR,0,0,0,0",
	  "1,IQUERY,1,0,1,0,0,0,NXDOMAIN,1,0,0,0",
          "1,QUERY,0,0,1,1,0,0,FORMERR,1,0,0,0",
	  "1,QUERY,0,0,0,1,0,0,SERVFAIL,1,0,0,0",
	  "1,QUERY,0,0,1,1,0,0,NOERROR,1,1,0,0",
	  "1,IQUERY,1,0,1,0,0,0,NOERROR,1,0,1,0", #iq80
	  "1,IQUERY,1,0,1,1,0,0,NOTIMP,1,0,0,0",
          "1,QUERY,0,0,1,1,0,0,NOERROR,1,0,0,0",
          "1,QUERY,1,0,1,1,0,0,NOERROR,1,1,1,.+",
          "1,QUERY,0,0,1,1,0,0,REFUSED,0,0,0,0",
          "1,UPDATE,0,0,0,1,0,0,NOTIMP,1,0,0,0",
          "1,QUERY,1,0,0,1,0,0,NXDOMAIN,1,0,0,0",
          "1,QUERY,0,0,0,1,0,0,NOTIMP,0,0,0,0",
          "1,QUERY,0,0,0,0,0,0,REFUSED,1,0,0,0",
          "1,QUERY,1,0,1,1,0,0,NXDOMAIN,1,0,0,0", #iq89
          "1,QUERY,1,0,0,0,0,0,NOERROR,1,1,0,0", #iq90
          "1,IQUERY,1,0,1,1,0,1,NOTIMP,1,0,0,0",
          "1,QUERY,0,0,0,1,0,0,NOTIMP,1,0,0,0",
          "1,QUERY,0,0,1,0,0,1,SERVFAIL,1,0,0,0",
          "1,QUERY,0,0,0,1,0,0,NOERROR,1,0,13,13", #iq94
          "1,QUERY,0,0,0,1,0,0,NOERROR,1,0,1,0", #iq95
          "1,QUERY,0,0,1,0,0,0,NOERROR,1,0,13,13",
          "1,IQUERY,1,0,0,0,0,0,NOTIMP,1,0,0,0", #iq97
          "1,IQUERY,1,0,0,0,1,1,NOTIMP,1,0,0,0", #iq98
          "1,IQUERY,0,0,1,1,0,0,NOERROR,1,0,1,0", #iq99
          "1,QUERY,.,0,1,0,0,0,NOERROR,1,0,0,0", #iq100
          "1,QUERY,0,0,1,0,0,0,NXDOMAIN,1,0,0,0", #101
);

my @ruleset = (
{ fingerprint => $iq[89], result => { vendor => "Simon Kelley", product => "dnsmasq", version =>""}, qv => "version.bind", },
  { fingerprint => ".+", header => $qy[0], query => ". IN A",  ruleset => [
    { fingerprint => "query timed out" , header => $qy[0],  query => "com. IN A", ruleset => [
          { fingerprint => "query timed out", header => $qy[7], query => ". CH A", ruleset => [
                 { fingerprint => "query timed out", header => $qy[6], query => ". IN A", ruleset => [
                        { fingerprint => $iq[38], result => { vendor => "Digital Lumber", product => "Oak DNS", version =>"" },  qv => "version.oak",}, 
                        { fingerprint => "query timed out", result => "TIMEOUT",}, 
                        { fingerprint => ".+", state => "q0tq0tq7tq6r?", }, ]
                 },
                 { fingerprint => $iq[35], result => { vendor => "XBILL", product => "jnamed (dnsjava)", version => "" }, },
                 { fingerprint => $iq[36], result => { vendor => "Men & Mice", product => "QuickDNS for MacOS Classic", version => ""}, }, 
                 { fingerprint => $iq[37], result => { vendor => "unknown", product => "NonSequitur DNS", version => ""}, },
                 { fingerprint => ".+", state => "q0tq0tq7r?", }, ]  
          },
	  { fingerprint => $iq[35], result => { vendor => "eNom", product => "eNom DNS", version =>""}, },
          { fingerprint => ".+", state => "q0tq0r?", },]
    },
 
    { fingerprint => $iq[0], header => $qy[1], query=> "jjjjjjjjjjjj IN A", ruleset => [
	  { fingerprint => $iq[12], result => { vendor => "ISC", product => "BIND", version => "8.4.1-p1" },  qv => "version.bind",},                         
	  { fingerprint => $iq[13], result => { vendor => "ISC", product => "BIND", version => "8 plus root server modifications"},  qv => "version.bind",}, 
          { fingerprint => $iq[15], result => { vendor => "Cisco", product => "CNR", version => ""}, },
	  { fingerprint => $iq[16], header => $qy[2], query => "hostname.bind CH TXT", ruleset => [
                  { fingerprint => $iq[58], result => { vendor => "ISC", product => "BIND", version => "8.3.0-RC1 -- 8.4.4"},  qv => "version.bind",},     
                  { fingerprint => $iq[50], result => { vendor => "ISC", product => "BIND", version => "8.3.0-RC1 -- 8.4.4"},  qv => "version.bind",},    
                  { fingerprint => $iq[48], result => { vendor => "ISC", product => "BIND", version => "8.2.2-P3 -- 8.3.0-T2A"},  qv => "version.bind",},
                  { fingerprint => ".+", state => "q0r0q1r16q2r?", },]
          },
          { fingerprint => ".+", state => "q0r0q1r?", },]
    },

    { fingerprint => $iq[1], header => $qy[2], query => ". IN IXFR", ruleset => [
          { fingerprint => $iq[31], result => { vendor => "Microsoft", product => "Windows DNS", version => "2000" }, },				
          { fingerprint => $iq[32], result => { vendor => "Microsoft", product => "Windows DNS", version => "NT4" }, },
          { fingerprint => $iq[50], result => { vendor => "Microsoft", product => "Windows DNS", version => "2003"}, },
          { fingerprint => ".+", state => "q0r1q2r?", }, ]
    },

    { fingerprint => $iq[2], header => $qy[1], ruleset => [
	  { fingerprint => $iq[11], result => { vendor => "ISC", product => "BIND", version => "9.2.3rc1 -- 9.4.0a4" }, qv => "version.bind",},    
	  { fingerprint => $iq[12], header => $qy[3], ruleset => [
		{ fingerprint => $iq[25], header => $qy[6], ruleset => [
                      { fingerprint => $iq[33], result => { vendor => "bboy", product => "MyDNS", version => "" },},				
                      { fingerprint => $iq[34], header => $qy[2],  query  => "012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.0123456789012345678901234567890123456789012345678901234567890. IN A", ruleset => [
                           { fingerprint => $iq[47], result => { vendor => "NLnetLabs", product => "NSD", version => "1.0.3 -- 1.2.1"}, qv => "version.server", }, 
                           { fingerprint => $iq[48], header => $qy[2],  query  => "hostname.bind CH TXT", ruleset => [
                                     { fingerprint => $iq[50], result => { vendor => "NLnetLabs", product => "NSD", version => "1.2.2" }, qv => "version.server", },
				     { fingerprint => $iq[51], header => $qy[8], query => ". IN A", ruleset => [
                                           { fingerprint => $iq[93], result => { vendor => "NLnetLabs", product => "NSD", version => "1.2.3 -- 2.1.2" } , qv => "version.server",  },
                                           { fingerprint => $iq[48], result => { vendor => "NLnetLabs", product => "NSD", version => "2.1.3" }, qv => "version.server",  }, 
                                           { fingerprint => ".+", state => "q0r2q1r12q3r25q6r34q2r48q2r51q8r?", }, ]
                                     },
                                     { fingerprint => ".+", state => "q0r2q1r12q3r25q6r34q2r48q2r?", }, ]
                           },
                           { fingerprint => $iq[49], header => $qy[2],  query  => "hostname.bind CH TXT", ruleset => [
                                     { fingerprint => $iq[50], result => { vendor => "NLnetLabs", product => "NSD", version => "1.2.2 [root]"} , qv => "version.server",  },
                                     { fingerprint => $iq[51], result => { vendor => "NLnetLabs", product => "NSD", version => "1.2.3 [root]"}, qv => "version.server", }, 
                                     { fingerprint => ".+", state => "q0r2q1r12q3r25q6r34q2r49q2r?", }, ]
                           },
                           { fingerprint => $iq[53], result => { vendor => "NLnetLabs", product=>"NSD", version => "1.0.2"}, qv => "version.server", },
                           { fingerprint => ".+", state => "q0r2q1r12q3r25q6r34q2a?", },]
                      },
                      { fingerprint => ".+", state => "q0r2q1r12q3r25q6r?", },]
                },
		{ fingerprint => $iq[26], result => { vendor => "VeriSign", product => "ATLAS", version => ""},}, 
                { fingerprint => ".+", state => "q0r2q1r12q3r?", },] 
          },
	  { fingerprint => $iq[15],  header => $qy[6], ruleset => [
               { fingerprint => $iq[45], result => { vendor => "Nominum", product =>"ANS", version =>""}, qv => "version.bind",},
               { fingerprint => $iq[65], result => { vendor => "ISC", product => "BIND", version => "9.2.3rc1 -- 9.4.0a4" },  qv => "version.bind",},
               { fingerprint => $iq[46], header => $qy[7], ruleset => [
                      { fingerprint => $iq[56], result => { vendor => "ISC", product => "BIND", version => "9.0.0b5 -- 9.0.1" }, qv => "version.bind",},
                      { fingerprint => $iq[57], result => { vendor => "ISC", product => "BIND", version => "9.1.0 -- 9.1.3" }, qv => "version.bind",}, 
                      { fingerprint => ".+", state => "q0r2q1r15q6r46q7r?", }, ]
               },
               { fingerprint => ".+", state => "q0r2q1r15q6r?", },]
          },
	  { fingerprint => $iq[16], header => $qy[4], ruleset => [
                { fingerprint => $iq[29], result => { vendor => "ISC", product => "BIND", version => "9.2.0a1 -- 9.2.0rc3"}, qv => "version.bind",},
                { fingerprint => $iq[30],  header => $qy[0], query  => ". A CLASS0" , ruleset => [
                        { fingerprint => $iq[2], result => { vendor=>"ISC", product => "BIND", version =>"9.2.0rc7 -- 9.2.2-P3"}, qv => "version.bind", },
                        { fingerprint => $iq[0], result => { vendor=>"ISC", product => "BIND", version =>"9.2.0rc4 -- 9.2.0rc6"}, qv => "version.bind", },
                        { fingerprint => ".+", result => { vendor => "ISC", product => "BIND", version =>"9.2.0rc4 -- 9.2.2-P3"}, qv => "version.bind", }, ]
                },
                { fingerprint => ".+", state => "q0r2q1r16q4r?", },]
          },
          { fingerprint => ".+", state => "q0r2q1r?", }, ]
    },
    
    { fingerprint => $iq[3], header => $qy[1], ruleset => [
          { fingerprint => "query timed out", header => $qy[5], ruleset => [
                { fingerprint => $iq[3], result => { vendor => "sourceforge", product =>"Dents", version =>""}, qv => "version.bind", },
                { fingerprint => $iq[81], result => { vendor => "Microsoft", product => "Windows DNS", version => "2003" },},
                { fingerprint => $iq[91], result => { vendor => "Microsoft", product => "Windows DNS", version => "2003" },},
                { fingerprint => ".+", state => "q0r3q1tq5r?", }, ]

          },     
	  { fingerprint => $iq[14], result => { vendor => "UltraDNS", product => "", version =>"v2.7.0.2 -- 2.7.3"}, qv => "version.bind", }, 
          { fingerprint => $iq[13], header => $qy[5], ruleset => [
                { fingerprint => $iq[39], result => { vendor => "pliant", product => "DNS Server", version =>""},},
                { fingerprint => $iq[7], result => { vendor => "JHSOFT", product => "simple DNS plus", version =>""}, }, 
		{ fingerprint => $iq[71], header => $qy[6], ruleset => [
                        { fingerprint => $iq[41], result => { vendor =>"Netnumber", product =>"ENUM server", version =>""}, },
                        { fingerprint => $iq[85], result => { vendor =>"Raiden", product => "DNSD", version => ""}, }, ]
                },
                { fingerprint => ".+", state => "q0r3q1r13q5r?", }, ]
                },
          { fingerprint => ".+", state => "q0r3q1r?", }, ]
    },
    
    { fingerprint => $iq[4], header => $qy[1], query=> "jjjjjjjjjjjj IN A", ruleset => [
          { fingerprint => $iq[17], result => { vendor => "ISC", product => "BIND", version =>"9.0.0b5 -- 9.0.1 [recursion enabled]"},qv => "version.bind", },
	  { fingerprint => $iq[18], header => $qy[5], query=> ". IN A" , ruleset => [
                { fingerprint => $iq[27], result => { vendor => "ISC", product => "BIND", version => "4.9.3 -- 4.9.11"}, qv => "version.bind", },
                { fingerprint => $iq[28], result => { vendor => "ISC", product => "BIND", version => "4.8 -- 4.8.3"}, }, 
                { fingerprint => ".+", state => "q0r4q1r18q5r?", }, ]
          },
          { fingerprint => $iq[19], result => {vendor => "ISC", product =>"BIND", version => "8.2.1 [recursion enabled]"}, qv => "version.bind", },           
	  { fingerprint => $iq[20], header => $qy[3], query=> ". IN A", ruleset => [
                { fingerprint => $iq[42], result => {vendor => "ISC", product =>"BIND", version =>"8.1-REL -- 8.2.1-T4B [recursion enabled]"}, qv => "version.bind", }, 
                { fingerprint => ".+", state => "q0r4q1r20q3r?", },]
          },
	  { fingerprint => $iq[21], header => $qy[2], query => "hostname.bind CH TXT", ruleset => [
                { fingerprint => $iq[60], result => {vendor =>"ISC", product => "BIND", version => "8.3.0-RC1 -- 8.4.4 [recursion enabled]"},  qv => "version.bind",},
                { fingerprint => $iq[59], header => $qy[7], query=> ". IN A", ruleset => [
			 { fingerprint => $iq[68], result => {vendor =>"ISC", product => "BIND", version => "8.1-REL -- 8.2.1-T4B [recursion enabled]"}, qv => "version.bind", },
                         { fingerprint => $iq[69], result => {vendor =>"ISC", product => "BIND", version => "8.2.2-P3 -- 8.3.0-T2A [recursion enabled]"},  qv => "version.bind",},
                         { fingerprint => "connection failed", result => { vendor =>"Runtop", product => "dsl/cable", version =>""},},
                	 { fingerprint => ".+", state => "q0r4q1r21q2r59q7r?", },]
                },

	        { fingerprint => $iq[58], result => {vendor => "ISC", product =>"BIND", version => "8.3.0-RC1 -- 8.4.4 [recursion local]"},  qv => "version.bind",},
                { fingerprint => $iq[50], result => {vendor => "ISC", product =>"BIND", version => "8.3.0-RC1 -- 8.4.4 [recursion local]"},  qv => "version.bind",},
		{ fingerprint => $iq[61], result => {vendor => "ISC", product =>"BIND", version => "8.3.0-RC1 -- 8.4.4 [recursion local]"},  qv => "version.bind",},
                { fingerprint => $iq[48], result => {vendor => "ISC", product =>"BIND", version => "8.2.2-P3 -- 8.3.0-T2A [recursion local]"},  qv => "version.bind",},
                { fingerprint => ".+", state => "q0r4q1r21q2r?", },]
          },
          { fingerprint => ".+", state => "q0r4q1r?", }, ]
    },

    { fingerprint => $iq[5], header => $qy[1], ruleset => [
          { fingerprint => $iq[11], result => { vendor => "ISC", product => "BIND", version => "9.2.3rc1 -- 9.4.0a4", option => "recursion enabled,split view" }, qv => "version.bind",},
	  { fingerprint => $iq[17], result => {vendor => "ISC", product =>"BIND", version => "9.2.3rc1 -- 9.4.0a4 [recursion enabled]"}, qv => "version.bind",},
          { fingerprint => $iq[18], header => $qy[5], ruleset => [
		{ fingerprint => $iq[5], header => $qy[7], query  => ". IN A", ruleset => [
	             { fingerprint => $iq[84], result => {vendor => "Nominum", product =>"CNS", version => ""}, qv => "version.bind",},
                     { fingerprint => $iq[59], result => {vendor => "Mikrotik", product =>"dsl/cable", version => ""}, },
                     { fingerprint => $iq[82], result => {vendor => "Mikrotik", product =>"dsl/cable", version => ""}, },
                     { fingerprint => ".+", state => "q0r5q1r18q5r5q7r?", }, ]
                },
                { fingerprint => $iq[64], result => "unknown, smells like old BIND 4", },
                { fingerprint => ".+", state => "q0r5q1r18q5r?", }, ]
          }, 
	  { fingerprint => $iq[20], header => $qy[7], ruleset => [
                { fingerprint => $iq[54], result => {vendor => "ISC", product =>"BIND", version => "9.0.0b5 -- 9.0.1 [recursion enabled]"}, qv => "version.bind",},
                { fingerprint => $iq[55], result => {vendor => "ISC", product =>"BIND", version => "9.1.0 -- 9.1.3 [recursion enabled]"}, qv => "version.bind",},
                { fingerprint => $iq[63], result => {vendor => "ISC", product =>"BIND", version => "4.9.3 -- 4.9.11 [recursion enabled]"}, qv => "version.bind",},
                { fingerprint => $iq[61], result => {vendor => "ISC", product =>"BIND", version => "9.0.0b5 -- 9.1.3 [recursion local]"}, qv => "version.bind",},
                { fingerprint => ".+", state => "q0r5q1r20q7r?", }, ]
          },   
	  { fingerprint => $iq[21], header => $qy[4], ruleset => [
	        { fingerprint => "query timed out", result => {vendor => "ISC", product =>"BIND", version => "9.2.0a1 -- 9.2.2-P3 [recursion enabled]"}, qv => "version.bind", },
                { fingerprint => $iq[29], result => {vendor => "ISC", product =>"BIND", version => "9.2.0a1 -- 9.2.0rc3 [recursion enabled]"}, qv => "version.bind", },
		{ fingerprint => $iq[61], header => $qy[0], query  => ". A CLASS0" , ruleset => [
                        { fingerprint => $iq[2], result => {vendor => "ISC", product =>"BIND", version => "9.2.0rc7 -- 9.2.2-P3 [recursion local]"}, qv => "version.bind", },
                        { fingerprint => $iq[0], result => {vendor => "ISC", product =>"BIND", version => "9.2.0a1 -- 9.2.0rc6 [recursion local]"}, qv => "version.bind", },
                        { fingerprint => ".+", result => {vendor => "ISC", product =>"BIND", version => "9.2.0a1 -- 9.2.2-P3 [recursion local]"}, qv => "version.bind", }, ]
                },
                { fingerprint => $iq[30], header => $qy[0], query  => ". A CLASS0" , ruleset => [
		 	{ fingerprint => $iq[2], result => {vendor => "ISC", product =>"BIND", version => "9.2.0rc7 -- 9.2.2-P3 [recursion enabled]"}, qv => "version.bind", },
                        { fingerprint => $iq[0], result => {vendor => "ISC", product =>"BIND", version => "9.2.0rc4 -- 9.2.0rc6 [recursion enabled]"}, qv => "version.bind", },
                        { fingerprint => ".+", result => {vendor => "ISC", product =>"BIND", version => "9.2.0rc4 -- 9.2.2-P3 [recursion enabled]"}, qv => "version.bind", }, ] 
                },
                { fingerprint => ".+", state => "q0r5q1r21q4r?", }, ]
          }, 
          { fingerprint => ".+", state => "q0r5q1r?", }, ]
    },
	 
    { fingerprint => $iq[6], header => $qy[1], ruleset => [
	  { fingerprint => $iq[15], result => {vendor => "incognito", product =>"DNS commander", version => "v2.3.1.1 -- 4.0.5.1"}, qv => "version.bind",  },
	  { fingerprint => $iq[19], header => $qy[3], ruleset => [
            	{ fingerprint => $iq[66], result => {vendor => "vermicelli", product =>"totd", version => ""}, },
                { fingerprint => $iq[67], result => {vendor => "JHSOFT", product =>"simple DNS plus", version => "[recursion enabled]"}, }, 
                { fingerprint => ".+", state => "q0r6q1r19q3r?", }, ]
          },
          { fingerprint => ".+", state => "q0r6q1r?", }, ]
    },
    
    { fingerprint => $iq[7], header => $qy[1], ruleset => [
	  { fingerprint => $iq[22], header => $qy[3], ruleset => [
                { fingerprint => $iq[97], result => {vendor => "PowerDNS", product =>"PowerDNS", version => "2.9.4 -- 2.9.19"}, qv => "version.bind", }, 
                { fingerprint => $iq[98], result => {vendor => "Stanford", product =>"lbnamed", version => "1.0.0 -- 2.3.2"}, },
                { fingerprint => ".+", state => "q0r7q1r22q3r?", }, ]
          },
          { fingerprint => $iq[24], result => {vendor => "PowerDNS", product =>"PowerDNS", version => "2.8 -- 2.9.3"}, qv => "version.bind", },
	  { fingerprint => ".+", state => "q0r7q1r?", }, ]
    },

    { fingerprint => $iq[8], header => $qy[1], ruleset => [
          { fingerprint => $iq[23], header => $qy[2] , query => ". CH A", ruleset => [
                { fingerprint => "query timed out", result => { vendor => "DJ Bernstein", product => "TinyDNS", version => "1.04"} ,},
                { fingerprint => $iq[32], result => {vendor => "DJ Bernstein", product => "TinyDNS", version => "1.05"} ,}, 
                { fingerprint => ".+", state => "q0r8q1r23q2r?",},]
          },
	  { fingerprint => ".+", state => "q0r8q1r?", }, ]
    },
    
    { fingerprint => $iq[9], header => $qy[1], ruleset => [
	  { fingerprint => $iq[9], result => { vendor => "Sam Trenholme", product =>"MaraDNS", version => ""}, qv => "erre-con-erre-cigarro.maradns.org"}, 
	  { fingerprint => ".+", state => "q0r9q1r?", }, ]
    },

    { fingerprint => $iq[10], result => { vendor => "Microsoft", product =>"?", version => ""}, },
    { fingerprint => $iq[26], result => { vendor => "Meilof Veeningen", product =>"Posadis", version =>""}, },
    { fingerprint => $iq[43], header => $qy[6], ruleset => [
                { fingerprint => $iq[34], result => { vendor => "Paul Rombouts", product =>"pdnsd", version =>""}, },
                { fingerprint => $iq[75], result => { vendor => "antirez", product =>"Yaku-NS", version =>""}, },
                { fingerprint => ".+", state => "q0r43q6r?", }, ]
    },

    { fingerprint => $iq[44], result => { vendor =>"cpan", product=>"Net::DNS Nameserver", version =>""}, qv => "version.bind", },
    { fingerprint => $iq[52], result => { vendor =>"NLnetLabs", product=>"NSD", version => "1.0 alpha"}, },
    { fingerprint => $iq[55], header => $qy[3], ruleset => [
                { fingerprint => $iq[94], result => { vendor =>"robtex", product=>"Viking DNS module", version=>""}, },
                { fingerprint => $iq[95], result => { vendor =>"cisco", product=>"dns resolver/server", version=>""}, },
                { fingerprint => ".+", state => "q0r55q3r?", }, ]
    },
    { fingerprint => $iq[59], result => { vendor =>"Max Feoktistov", product=>"small HTTP server [recursion enabled]", version =>""}, },
    { fingerprint => $iq[60], result => { vendor =>"Axis", product=>"video server", version =>""}, },
    { fingerprint => $iq[62], header => $qy[7], query => "1.0.0.127.in-addr.arpa. IN PTR", ruleset => [
                { fingerprint => $iq[62], result => { vendor =>"Michael Tokarev", product=>"rbldnsd",version=>""}, qv => "version.bind", },
                { fingerprint => $iq[79], result => { vendor =>"4D", product=>"WebSTAR", version=>""}, },
                { fingerprint => $iq[83], result => { vendor =>"Netopia", product =>"dsl/cable", version => ""},},
                { fingerprint => $iq[90], result => { vendor =>"TZO", product=>"Tzolkin DNS",version=>""}, },
                { fingerprint => "query timed out", result => { vendor =>"Netopia", product =>"dsl/cable", version=>""},},
                { fingerprint => ".+", state => "q0r62q7r?", }, ]
    },
    { fingerprint => $iq[70], result => { vendor =>"Yutaka Sato", product=>"DeleGate DNS", version=>""},},
    { fingerprint => $iq[72], result => { vendor =>"", product =>"sheerdns", version=>""}, },
    { fingerprint => $iq[73], result => { vendor =>"Matthew Pratt", product=>"dproxy", version=>""}, },
    { fingerprint => $iq[74], result => { vendor =>"Brad Garcia", product=>"dnrd",version=>""}, },
    { fingerprint => $iq[76], result => { vendor =>"Sourceforge", product=>"JDNSS",version=>""}, },
    { fingerprint => $iq[77], result => { vendor =>"Dan Kaminsky", product=>"nomde DNS tunnel",version=>""}, },
    { fingerprint => $iq[78], result => { vendor =>"Max Feoktistov", product=>"small HTTP server", version =>""}, },
    { fingerprint => $iq[79], result => { vendor =>"robtex", product=>"Viking DNS module", version=>""}, },
    { fingerprint => $iq[80], result => { vendor =>"Fasthosts", product=>"Envisage DNS server", version=>""}, },
    { fingerprint => $iq[81], result => { vendor =>"WinGate", product=>"Wingate DNS", version=>""},},
    { fingerprint => $iq[82], result => { vendor =>"Ascenvision", product=>"SwiftDNS", version=>""},},
    { fingerprint => $iq[86], result => { vendor =>"Nortel Networks", product=>"Instant Internet",version=>""}, },
    { fingerprint => $iq[87], result => { vendor =>"ATOS", product=>"Stargate ADSL", version=>""},},
    { fingerprint => $iq[88], result => { vendor =>"3Com", product=>"Office Connect Remote", version=>""},},
    { fingerprint => $iq[89], result => { vendor =>"Alteon", product=>"ACEswitch", version=>""},},
    { fingerprint => $iq[90], result => { vendor =>"javaprofessionals", product=>"javadns/jdns", version=>""},},
    { fingerprint => $iq[92], result => { vendor =>"Beehive", product=>"CoDoNS",version=>""}, },
    { fingerprint => $iq[96], result => { vendor =>"Beevihe", product=>"AAAAAA",version=>""}, qv => "version.bind", },
    { fingerprint => $iq[100], result => { vendor =>"ValidStream", product=>"ValidDNS",version=>""}, },
    { fingerprint => $iq[101], result => { vendor =>"ValidStream", product=>"ValidDNS",version=>""}, },
    { fingerprint => ".+", state => "q0r?", }, 

] },

);

######################################################################

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = {};

    my %config = @_;

    for my $k (keys %default) {
	if (defined $config{$k}) {
	    $self->{$k} = $config{$k};
	} else {
	    $self->{$k} = $default{$k};
	}
    }

    bless $self, $class;
    return $self;
}

sub hash
{
    my $self = shift;

    my $addr = shift;
    my $port = shift;

    $port = 53 unless($port);

    return $self->init($addr, $port);
}

sub string
{
    my $self = shift;

    my $addr = shift;
    my $port = shift;

    $port = 53 unless($port);

    my %r = $self->hash($addr, $port);

    my @s = ();

    if (defined $r{error}) {
	push @s, $r{error};
    } elsif (defined $r{result}) {
	push @s, $r{result};
    } else {
	push @s, $r{vendor}  if(defined $r{vendor});
	push @s, $r{product} if(defined $r{product});
	push @s, $r{version} if(defined $r{version});
	push @s, "[$r{option}]" if(defined $r{option});
    }

    push @s, $r{vstring} if(defined $r{vstring});

    push @s, "($r{state};$r{id})" if($self->{debug});

    return join($self->{separator}, @s);
}

sub query_version
{  
    my $self = shift;

    my $qserver = shift;
    my $qport   = shift;
    my $ident   = shift;

    my $rrset = " id: ";
    my $resolver = Net::DNS::Resolver->new;

    $resolver->nameservers($qserver);
    $resolver->port($qport);
    $resolver->srcaddr($self->{source});
    $resolver->retry($self->{retry});
    $resolver->retrans($self->{timeout});
    $resolver->usevc($self->{forcetcp});
    my $query = $resolver->query($ident, 'TXT', 'CH');

    if ($query && $query->header->ancount > 0) {
        for my $rr ($query->answer) {
            ($rrset = $rrset . "\"" . $rr->txtdata . "\" ") if ($rr->type eq "TXT");
        }
       $rrset =~ s/\n/\" \"/g;
       if (length($rrset) > $versionlength) {
          $rrset = substr($rrset,0,$versionlength)."..."
       }
       return $rrset;
    }

    return " id unavailable (".$resolver->errorstring.")";
}

sub init
{
    my $self = shift;

    my $qserver = shift;
    my $qport   = shift;

    return $self->process($qserver, $qport,
			  $initrule{header}, $initrule{query}, \@ruleset);
}

sub process
{
    my $self = shift;

    my $qserver = shift;
    my $qport   = shift;
    my $qheader = shift;
    my $qstring = shift;
    my $ruleref = shift;
    my $ver;
    my $id;
    my %ret;

    if ($self->{debug}) {
	print STDERR "==> PROCESS $qserver:$qport $qheader $qstring\n";
	print STDERR "\n";
    }

    my ($answer, $ress) = $self->probe($qserver, $qport,
				       $qheader, $qstring);

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
		$ver = $self->query_version($qserver, $qport,
					    $rule->{qv}) if $self->{qversion};
	    }
            if ($self->{qchaos}) {
		$ver = $self->query_version($qserver, $qport,
					    "version.bind");
	    }
	    $ret{vstring} = $ver if($ver);

	    if (ref($rule->{result})) {
		$ret{vendor}  = $rule->{result}{vendor};
		$ret{product} = $rule->{result}{product};
		$ret{version} = $rule->{result}{version};
		$ret{option}  = $rule->{result}{option};
	    } else {		
		$ret{result} = $rule->{result};
	    }

	    return %ret;
	}

        # print state if no matches
        if (defined $rule->{state}) {
            $ver = $self->query_version($qserver, $qport,
					"hostname.bind") if $self->{qversion};
	    $ret{vstring} = $ver if($ver);

	    $ret{error} = "No match found";
	    $ret{state} = $rule->{state};
	    $ret{id} = $id;

	    return %ret;
        }

	# update query if defined
	if (defined $rule->{query}) {
	    $qstring = $rule->{query};
	}

	# recurse if we have a new header and a new ruleset
	if (defined $rule->{header} && defined $rule->{ruleset}) {
	    return $self->process($qserver, $qport,
				  $rule->{header}, $qstring, $rule->{ruleset});
	}

	die "syntax error";
    }

    return %ret;
}

sub header2fp
{
    my $header = shift;

    my @list = ($header->qr, 
		$header->opcode,
		$header->aa,
		$header->tc,
		$header->rd,
		$header->ra,
		$header->ad,
		$header->cd,
		$header->rcode,
		$header->qdcount,
		$header->ancount,
		$header->nscount,
		$header->arcount);

    return join(",", @list);
}

sub fp2header
{
    my @list = split(/,/, shift);

    my $header = Net::DNS::Header->new;

    $header->qr(shift @list);
    $header->opcode(shift @list);
    $header->aa(shift @list);
    $header->tc(shift @list);
    $header->rd(shift @list);
    $header->ra(shift @list);
    $header->ad(shift @list);
    $header->cd(shift @list);
    $header->rcode(shift @list);
    $header->qdcount(shift @list);
    $header->ancount(shift @list);
    $header->nscount(shift @list);
    $header->arcount(shift @list);

    return $header;
}

sub probe
{
    my $self = shift;

    my $qserver = shift;
    my $qport = shift;
    my $qheader = shift;
    my @qstring = split(/ /, shift);

    my $header = fp2header($qheader);

    my $packet = Net::DNS::Packet->new(\$header->data);
    $packet->push("question", Net::DNS::Question->new(@qstring));

    if ($self->{debug}) {
	print STDERR "==> QUERY BEGIN\n";
	print STDERR $packet->print, "\n";
	print STDERR "==> QUERY END\n";
	print STDERR "\n";
    }

    my $resolver =  Net::DNS::Resolver->new;
    $resolver->nameservers($qserver);
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

sub version
{
    return $VERSION;
}

1;
