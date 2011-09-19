/* 
 * File:   functions.h
 * Author: sjobe
 *
 * Created on April 5, 2011, 10:52 AM
 */

#ifndef FUNCTIONS_H
#define	FUNCTIONS_H


#include <vantages/dns_packet.h>


unsigned int str_to_ip(char *ipstr);

void printHeader(DnsHeader &header);
void printNameClassType(DnsPacket &packet);

#endif	/* FUNCTIONS_H */

