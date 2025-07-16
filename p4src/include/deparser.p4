#ifndef _DEPARSER_P4_
#define _DEPARSER_P4_

#include <core.p4>
#include <v1model.p4>

#include "headers.p4"

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ddos);
        packet.emit(hdr.ipv4);
    }
}

#endif  /* _DEPARSER_P4_ */
