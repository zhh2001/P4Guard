#ifndef _PARSER_P4_
#define _PARSER_P4_

#include <core.p4>
#include <v1model.p4>

#include "headers.p4"

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_DDOS: parse_ddos;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ddos {
        packet.extract(hdr.ddos);
        transition select(hdr.ddos.ether_type) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

#endif  /* _PARSER_P4_ */
