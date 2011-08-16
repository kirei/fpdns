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
". ANY NSEC",    #nct8
". CH IXFR",    #nct9
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
"1,QUERY,0,0,1,1,0,0,REFUSED,1,0,0,0",    #iq17
"0,QUERY,0,0,1,0,0,0,NOERROR,1,0,0,0",    #iq18
);
my @ruleset = (
{ fingerprint => $iq[0], result => { vendor =>"VENDOR", product=>"NSD 3.1.0, NSD 3.1.1, NSD 3.2.0, NSD 3.2.1, NSD 3.2.2, NSD 3.2.3, NSD 3.2.4, NSD 3.2.5, NSD 3.2.6, NSD 3.2.7, NSD 3.2.8, ",version=>"VERSION"}, },
{ fingerprint => $iq[1], result => { vendor =>"VENDOR", product=>"SuperDNS, ",version=>"VERSION"}, },
{ fingerprint=>$iq[2], header=>$qy[1], query=>$nct[1], ruleset => [
  { fingerprint => $iq[3], result => { vendor =>"VENDOR", product=>"BIND 9.1.1, BIND 9.1.2, BIND 9.1.3, ",version=>"VERSION"}, },
  { fingerprint=>$iq[4], header=>$qy[2], query=>$nct[2], ruleset => [
    { fingerprint => $iq[5], result => { vendor =>"VENDOR", product=>"BIND 9.2.0rc3",version=>"VERSION"}, },
    { fingerprint => $iq[6], result => { vendor =>"VENDOR", product=>"BIND 9.2.0, BIND 9.2.0rc6, BIND 9.2.1, BIND 9.2.2-P3, BIND 9.2.2, ",version=>"VERSION"}, },
    ]},
  { fingerprint=>$iq[7], header=>$qy[3], query=>$nct[3], ruleset => [
    { fingerprint => $iq[8], result => { vendor =>"VENDOR", product=>"BIND 9.2.3, BIND 9.2.4, BIND 9.2.5, BIND 9.2.6, BIND 9.2.7, BIND 9.2.8, BIND 9.2.9, ",version=>"VERSION"}, },
    { fingerprint=>$iq[9], header=>$qy[4], query=>$nct[4], ruleset => [
      { fingerprint=>$iq[10], header=>$qy[5], query=>$nct[5], ruleset => [
        { fingerprint => $iq[11], result => { vendor =>"VENDOR", product=>"BIND 9.7.2",version=>"VERSION"}, },
        { fingerprint => $iq[12], result => { vendor =>"VENDOR", product=>"BIND 9.6.3, BIND 9.7.3, ",version=>"VERSION"}, },
        ]},
      { fingerprint=>$iq[13], header=>$qy[6], query=>$nct[6], ruleset => [
        { fingerprint => $iq[2], result => { vendor =>"VENDOR", product=>"BIND 9.3.0, BIND 9.3.1, BIND 9.3.2, BIND 9.3.3, BIND 9.3.4, BIND 9.3.5, BIND 9.3.6-P1, BIND 9.3.6, ",version=>"VERSION"}, },
        { fingerprint=>$iq[14], header=>$qy[7], query=>$nct[7], ruleset => [
          { fingerprint => $iq[15], result => { vendor =>"VENDOR", product=>"BIND 9.4.0, BIND 9.4.0a5, BIND 9.4.0b4, BIND 9.4.1, BIND 9.4.2, BIND 9.4.3, BIND 9.5.0, BIND 9.5.1, ",version=>"VERSION"}, },
          { fingerprint=>$iq[6], header=>$qy[5], query=>$nct[5], ruleset => [
            { fingerprint => $iq[11], result => { vendor =>"VENDOR", product=>"BIND 9.6.0",version=>"VERSION"}, },
            { fingerprint => $iq[12], result => { vendor =>"VENDOR", product=>"BIND 9.5.2, BIND 9.6.1, BIND 9.6.2, BIND 9.7.0, BIND 9.7.1, ",version=>"VERSION"}, },
            ]},
          ]},
        ]},
      ]},
    ]},
  ]},
{ fingerprint=>$iq[16], header=>$qy[8], query=>$nct[8], ruleset => [
  { fingerprint => $iq[17], result => { vendor =>"VENDOR", product=>"Unbound 1.3.0, Unbound 1.3.1, Unbound 1.3.2, Unbound 1.3.3, Unbound 1.3.4, Unbound 1.4.0, ",version=>"VERSION"}, },
  { fingerprint=>$iq[6], header=>$qy[9], query=>$nct[9], ruleset => [
    { fingerprint => "header section incomplete", result => { vendor =>"VENDOR", product=>"Unbound 1.4.1, Unbound 1.4.2, Unbound 1.4.3, Unbound 1.4.4, Unbound 1.4.5, Unbound 1.4.6, Unbound 1.4.7, Unbound 1.4.8, Unbound 1.4.9, ",version=>"VERSION"}, },
    { fingerprint => $iq[12], result => { vendor =>"VENDOR", product=>"Unbound 1.4.10, Unbound 1.4.11, Unbound 1.4.12, ",version=>"VERSION"}, },
    ]},
  ]},
);