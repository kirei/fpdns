#include "functions.h"

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <vantages/dns_defs.h>
#include <vantages/dns_resolver.h>
#include <vantages/dns_packet.h>
#include <vantages/dns_opt.h>
#include <vantages/dns_a.h>
#include <vantages/dns_err.h>
#include <vantages/dns_name.h>


#define NUM_OPCODE 16
#define NUM_AA 2
#define NUM_TC 2
#define NUM_RD 2
#define NUM_RA 2
#define NUM_Z 2
#define NUM_AD 2
#define NUM_CD 2
#define NUM_RCODE 2

#define NUM_QNAME 2
#define NUM_QCLASS 9
#define NUM_QTYPE 24

#define DNS_CLASS_RESERVED 0
#define DNS_CLASS_IN 1
#define DNS_CLASS_UNASSIGNED 2
#define DNS_CLASS_CH 3
#define DNS_CLASS_HS 4
#define DNS_CLASS_NONE 254
#define DNS_CLASS_ANY 255
#define DNS_CLASS_RESERVED_PRIVATE 65280
#define DNS_CLASS_RESERVED1 65535

#define DNS_RR_UNASSIGNED 32770
#define DNS_RR_PRIVATE 65280
#define DNS_RR_RESERVED 65535

// Important to always update this if anything about
// the way the responses are output is modified
#define RESPONSE_COLLECTOR_VERSION "0.1"

int main(int argc, char** argv) {

    //TODO: Check argc for right number of arguments

    bool showQueries = (strcmp(argv[1], "--show-queries") == false);

    DnsPacket oQuest(true, -1);

    DnsResolver oRes;
    oRes.setRetries(1);
    oRes.setTimeout(5);

    if(!showQueries){
    oRes.setNameserver(str_to_ip(argv[2]));
    }
    std::string sA = ".";
    DnsName oName(sA);

    DnsRR *pQuestionRR = DnsRR::question(oName, DNS_RR_A);
    pQuestionRR->set_class(DNS_CLASS_IN);
    oQuest.addQuestion(*pQuestionRR);

    int count = 0;
    unsigned opcode;
    unsigned aa;
    unsigned tc;
    unsigned rd;
    unsigned ra;
    unsigned z;
    unsigned ad;
    unsigned cd;
    unsigned rcode_index;
    rcode_t rcodes[NUM_RCODE] = {DNS_NOERROR, DNS_NOTIMP};

    if (showQueries) {
        fprintf(stdout, "ver %s\n", RESPONSE_COLLECTOR_VERSION);
    } else {
        fprintf(stdout, "%s\n", argv[1]);
    }
    
    for (opcode = 0; opcode < NUM_OPCODE; opcode++) {
        for (aa = 0; aa < NUM_AA; aa++) {
            for (tc = 0; tc < NUM_TC; tc++) {
                for (rd = 0; rd < NUM_RD; rd++) {
                    for (ra = 0; ra < NUM_RA; ra++) {
                        for (z = 0; z < NUM_Z; z++) {
                            for (ad = 0; ad < NUM_AD; ad++) {
                                for (cd = 0; cd < NUM_CD; cd++) {
                                    for (rcode_index = 0; rcode_index < NUM_RCODE; rcode_index++) {
                                        DnsPacket oResp(true);

                                        oQuest.getHeader().setOpcode(opcode);
                                        oQuest.getHeader().set_aa(aa);
                                        oQuest.getHeader().set_tc(tc);
                                        oQuest.getHeader().set_rd(rd);
                                        oQuest.getHeader().set_ra(ra);
                                        oQuest.getHeader().set_z(z);
                                        oQuest.getHeader().set_ad(ad);
                                        oQuest.getHeader().set_cd(cd);
                                        oQuest.getHeader().set_rcode(rcodes[rcode_index]);

                                        if (showQueries) {
                                            printHeader(oQuest.getHeader());
                                            printNameClassType(oQuest);
                                            continue;
                                        }

                                        oRes.send(oQuest, oResp);
                                        if (!oResp.getHeader().getResponse()) {
                                            printHeader(oQuest.getHeader());
                                        } else {
                                            printHeader(oResp.getHeader());
                                        }
                                        count++;

                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }


    std::string qnames[NUM_QNAME] = {".", "jjjjjjjjjjjj"};
    unsigned qclasses[NUM_QCLASS] = {DNS_CLASS_RESERVED, DNS_CLASS_IN,
        DNS_CLASS_UNASSIGNED, DNS_CLASS_CH, DNS_CLASS_HS, DNS_CLASS_NONE,
        DNS_CLASS_ANY, DNS_CLASS_RESERVED_PRIVATE, DNS_CLASS_RESERVED1};
    unsigned qtypes[NUM_QTYPE] = {DNS_RR_A, DNS_RR_NS, DNS_RR_MD, DNS_RR_CNAME,
        DNS_RR_SOA, DNS_RR_HINFO, DNS_RR_AAAA, DNS_RR_NXT, DNS_RR_A6, DNS_RR_DNAME,
        DNS_RR_SINK, DNS_RR_SSHFP, DNS_RR_RRSIG, DNS_RR_NSEC, DNS_RR_DNSKEY,
        DNS_RR_NSEC3, DNS_RR_NSEC3PARAM, DNS_RR_TKEY, DNS_RR_TSIG, DNS_RR_IXFR,
        DNS_RR_AXFR, DNS_RR_UNASSIGNED, DNS_RR_PRIVATE, DNS_RR_RESERVED};


    for (int i = 0; i < NUM_QNAME; i++) {
        for (int j = 0; j < NUM_QCLASS; j++) {
            for (int k = 0; k < NUM_QTYPE; k++) {

                DnsPacket oResp(true);
                DnsPacket oQuest(true, -1);

                DnsResolver oRes;
                oRes.setRetries(1);
                oRes.setTimeout(5);
                if(!showQueries){
                oRes.setNameserver(str_to_ip(argv[2]));
                }
                std::string sA = qnames[i];
                DnsName oName(sA);

                DnsRR *pQuestionRR = DnsRR::question(oName, qtypes[k]);
                pQuestionRR->set_class(qclasses[j]);
                oQuest.addQuestion(*pQuestionRR);

                if (showQueries) {
                    printHeader(oQuest.getHeader());
                    printNameClassType(oQuest);
                    continue;
                }


                oRes.send(oQuest, oResp);
                if (!oResp.getHeader().getResponse()) {
                    printHeader(oQuest.getHeader());
                } else {
                    printHeader(oResp.getHeader());
                }
                count++;
            }
        }
    }


    return 0;
}