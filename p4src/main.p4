#include <core.p4>
#include <v1model.p4>

#include "include/checksum.p4"
#include "include/deparser.p4"
#include "include/egress.p4"
#include "include/global.p4"
#include "include/headers.p4"
#include "include/ingress.p4"
#include "include/parser.p4"

V1Switch(
    p=MyParser(),
    vr=MyVerifyChecksum(),
    ig=MyIngress(),
    eg=MyEgress(),
    ck=MyComputeChecksum(),
    dep=MyDeparser()
) main;
