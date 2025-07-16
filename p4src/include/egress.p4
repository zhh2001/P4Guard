#ifndef _EGRESS_P4_
#define _EGRESS_P4_

#include <core.p4>
#include <v1model.p4>

#include "global.p4"
#include "headers.p4"

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.instance_type == INSTANCE_TYPE_CLONE) {
            hdr.ddos.setValid();
            hdr.ddos.pktNum = meta.pktNum;
            hdr.ddos.srcEntropy = meta.srcEntropy;
            hdr.ddos.srcEWMA = meta.srcEWMA;
            hdr.ddos.srcEWMMD = meta.srcEWMMD;
            hdr.ddos.dstEntropy = meta.dstEntropy;
            hdr.ddos.dstEWMA = meta.dstEWMA;
            hdr.ddos.dstEWMMD = meta.dstEWMMD;
            hdr.ddos.alarm = meta.alarm;
            hdr.ddos.drState = meta.drState;
            hdr.ddos.etherType = hdr.ethernet.etherType;
            hdr.ethernet.etherType = TYPE_DDOS;
        }
    }
}

#endif  /* _EGRESS_P4_ */
