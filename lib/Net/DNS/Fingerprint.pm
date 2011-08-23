#!/usr/bin/perl
#
# $Id: Fingerprint.pm,v 1.17 2005/09/05 13:33:36 jakob Exp $
#
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

our $VERSION = "0.9.3";

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
my @qy = (
"0,QUERY,0,0,0,0,0,0,NOERROR,0,0,0,0",    #qy0
"0,NS_NOTIFY_OP,1,1,0,1,0,0,NOERROR,0,0,0,0",    #qy1
"0,QUERY,1,0,1,0,0,1,NOTIMP,0,0,0,0",    #qy2
"0,STATUS,1,1,1,0,0,1,NOTIMP,0,0,0,0",    #qy3
"0,UPDATE,0,1,1,0,0,0,NOTIMP,0,0,0,0",    #qy4
"0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",    #qy5
"0,QUERY,0,1,0,0,0,1,NOERROR,0,0,0,0",    #qy6
"0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",    #qy7
"0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",    #qy8
"0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",    #qy9
);

my @nct = (
". IN A",    #nct0
". IN A",    #nct1
". IN A",    #nct2
". IN A",    #nct3
". IN A",    #nct4
"jjjjjjjjjjjj. CH A",    #nct5
". IN A",    #nct6
". IN DNSKEY",    #nct7
". CH IXFR",    #nct8
". ANY TKEY",    #nct9
);

my %initrule = (header => $qy[0], query  => $nct[0], );
my @iq = (
"1,QUERY,0,0,0,0,0,0,SERVFAIL,1,0,0,0",    #iq0
"1,QUERY,0,0,0,0,0,0,NOERROR,1,0,13,0",    #iq1
"1,QUERY,0,0,0,1,0,0,NOERROR,.+,.+,.+,.+",    #iq2
"1,NS_NOTIFY_OP,0,0,0,1,0,0,REFUSED,1,0,0,0",    #iq3
"1,NS_NOTIFY_OP,0,0,0,1,0,0,SERVFAIL,1,0,0,0",    #iq4
"1,QUERY,0,0,1,1,0,0,NOTIMP,1,0,1,0",    #iq5
"1,QUERY,0,0,1,1,0,0,NOERROR,.+,.+,.+,.+",    #iq6
"1,NS_NOTIFY_OP,0,0,0,1,0,0,FORMERR,1,0,0,0",    #iq7
"1,STATUS,0,0,1,1,0,0,NOTIMP,0,0,0,0",    #iq8
"1,STATUS,0,0,1,1,0,1,NOTIMP,0,0,0,0",    #iq9
"1,UPDATE,0,0,1,1,0,0,FORMERR,1,0,0,0",    #iq10
"1,QUERY,0,0,1,0,0,0,SERVFAIL,1,0,0,0",    #iq11
"1,QUERY,0,0,1,0,0,0,REFUSED,1,0,0,0",    #iq12
"1,UPDATE,0,0,1,1,0,0,FORMERR,0,0,0,0",    #iq13
"1,QUERY,0,0,0,1,0,1,NOERROR,.+,.+,.+,.+",    #iq14
"1,QUERY,0,1,1,1,0,0,NOERROR,.+,.+,.+,.+",    #iq15
"1,QUERY,0,0,0,0,0,0,REFUSED,0,0,0,0",    #iq16
"0,QUERY,0,0,1,0,0,0,NOERROR,1,0,0,0",    #iq17
"1,QUERY,0,0,1,1,0,0,REFUSED,1,0,0,0",    #iq18
);
my @ruleset = (
{ fingerprint => $iq[0], result => { vendor =>"NLnetLabs", product=>"NSD", version=>"3.1.0 -- 3.2.8"}, },
{ fingerprint => $iq[1], result => { vendor =>"", product=>"SuperDNS", version=>""}, },
{ fingerprint=>$iq[2], header=>$qy[1], query=>$nct[1], ruleset => [
  { fingerprint => $iq[3], result => { vendor =>"ISC", product=>"BIND", version=>"9.1.1 -- 9.1.3"}, },
  { fingerprint=>$iq[4], header=>$qy[2], query=>$nct[2], ruleset => [
    { fingerprint => $iq[5], result => { vendor =>"ISC", product=>"BIND", version=>"9.2.0rc3"}, },
    { fingerprint => $iq[6], result => { vendor =>"ISC", product=>"BIND", version=>"9.2.0 -- 9.2.2-P3"}, },
    ]},
  { fingerprint=>$iq[7], header=>$qy[3], query=>$nct[3], ruleset => [
    { fingerprint => $iq[8], result => { vendor =>"ISC", product=>"BIND", version=>"9.2.3 -- 9.2.9"}, },
    { fingerprint=>$iq[9], header=>$qy[4], query=>$nct[4], ruleset => [
      { fingerprint=>$iq[10], header=>$qy[5], query=>$nct[5], ruleset => [
        { fingerprint => $iq[11], result => { vendor =>"ISC", product=>"BIND", version=>"9.7.2"}, },
        { fingerprint => $iq[12], result => { vendor =>"ISC", product=>"BIND", version=>"9.6.3 -- 9.7.3"}, },
        ]},
      { fingerprint=>$iq[13], header=>$qy[6], query=>$nct[6], ruleset => [
        { fingerprint => $iq[2], result => { vendor =>"ISC", product=>"BIND", version=>"9.3.0 -- 9.3.6-P1"}, },
        { fingerprint=>$iq[14], header=>$qy[7], query=>$nct[7], ruleset => [
          { fingerprint => $iq[15], result => { vendor =>"ISC", product=>"BIND", version=>"9.4.0 -- 9.5.1"}, },
          { fingerprint=>$iq[6], header=>$qy[5], query=>$nct[5], ruleset => [
            { fingerprint => $iq[11], result => { vendor =>"ISC", product=>"BIND", version=>"9.6.0"}, },
            { fingerprint => $iq[12], result => { vendor =>"ISC", product=>"BIND", version=>"9.5.2 -- 9.7.1"}, },
            ]},
          ]},
        ]},
      ]},
    ]},
  ]},
{ fingerprint=>$iq[16], header=>$qy[8], query=>$nct[8], ruleset => [
  { fingerprint => $iq[12], result => { vendor =>"NLnetLabs", product=>"Unbound", version=>"1.4.10 -- 1.4.12"}, },
  { fingerprint=>"header section incomplete", header=>$qy[9], query=>$nct[9], ruleset => [
    { fingerprint => $iq[6], result => { vendor =>"NLnetLabs", product=>"Unbound", version=>"1.4.1 -- 1.4.9"}, },
    { fingerprint => $iq[18], result => { vendor =>"NLnetLabs", product=>"Unbound", version=>"1.3.0 -- 1.4.0"}, },
    ]},
  ]},
);

######################################################################

sub new
{
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my $self = {};

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

push @s, $r{state} if (defined $r{state} && $self->{debug});

return join(" ", @s);
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
    foreach my $rr ($query->answer) {
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
      $ret{state}   = $rule->{result}{state};
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
  $resolver->recurse($header->rd);
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