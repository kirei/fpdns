#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <vantages/dns_rr.h>
#include <vantages/dns_name.h>

#include "functions.h"

unsigned int str_to_ip(char *ipstr) {
    int iRet = 0;

    struct in_addr tAddr;
    memset(&tAddr, 0, sizeof (tAddr));
    int iLen = strlen(ipstr);
    if (iLen > 15) {
        //fprintf(stderr, "IPv4 addresses are not that long (%d chars)\n", iLen);
    } else if (!inet_pton(AF_INET, ipstr, &tAddr)) {
        //fprintf(stderr, "Unable to convert IP '%s' to number.\n", ipstr);
    } else {
        //fprintf(stdout, "'%s' -> %d\n", ipstr, (unsigned) htonl(tAddr.s_addr));
        iRet = (unsigned) htonl(tAddr.s_addr);
    }

    return iRet;
}

void printHeader(DnsHeader &header) {
    int opcode = header.getOpcode();
    
    fprintf(stdout, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", header.response(),
            opcode, header.get_aa(), header.get_tc(), header.get_rd(), header.get_ra(),
            header.get_ad(), header.get_cd(), header.rcode(), header.qd_count(), header.an_count(),
            header.ns_count(), header.ar_count());

}

void printNameClassType(DnsPacket &packet) {
    RRList_t questions;
    packet.getQuestions(questions);
    DnsRR* question = questions.front();
    fprintf(stdout, "%s %d %d\n",
            question->get_name()->toString().c_str(),
            question->get_class(),
            (int)question->type());
}
