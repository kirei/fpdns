/*
    Copyright (c) 2011 Verisign, Inc. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
    3. The name of the authors may not be used to endorse or promote products
       derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
    IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
    IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
    NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
    THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <vantages/dns_rr.h>
#include <vantages/dns_name.h>

#include "functions.h"

/**
 * Convert a C styled string to an int representing an ip address
 * @param ipstr
 * @return an int representing an ip address
 */
unsigned int str_to_ip(char *ipstr) {
    int iRet = 0;

    struct in_addr tAddr;
    memset(&tAddr, 0, sizeof (tAddr));
    int iLen = strlen(ipstr);
    if (iLen > 15) {
        fprintf(stderr, "IPv4 addresses are not that long (%d chars)\n", iLen);
    } else if (!inet_pton(AF_INET, ipstr, &tAddr)) {
        fprintf(stderr, "Unable to convert IP '%s' to number.\n", ipstr);
    } else {
        iRet = (unsigned) htonl(tAddr.s_addr);
    }

    return iRet;
}

/**
 * Output the header to stdout
 * @param header
 */
void printHeader(DnsHeader &header) {
    int opcode = header.getOpcode();
    
    fprintf(stdout, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", header.response(),
            opcode, header.get_aa(), header.get_tc(), header.get_rd(), header.get_ra(),
            header.get_ad(), header.get_cd(), header.rcode(), header.qd_count(), header.an_count(),
            header.ns_count(), header.ar_count());

}

/**
 * Output the name, class and type to stdout
 * @param packet
 */
void printNameClassType(DnsPacket &packet) {
    RRList_t questions;
    packet.getQuestions(questions);
    DnsRR* question = questions.front();
    fprintf(stdout, "%s %d %d\n",
            question->get_name()->toString().c_str(),
            question->get_class(),
            (int)question->type());
}
