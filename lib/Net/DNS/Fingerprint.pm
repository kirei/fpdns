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

require "fingerprint.pl";

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

push @s, "($r{state};$r{id})" if($self->{debug});

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
  $resolver->recurse($header->rd);
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
  $resolver->recurse($header->rd); #New addition
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