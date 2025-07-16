#ifndef _HEADERS_P4_
#define _HEADERS_P4_

#include <core.p4>
#include <v1model.p4>

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<16> etherType_t;
typedef bit<6>  dscp_t;
typedef bit<2>  ecn_t;
typedef bit<32> ip4Addr_t;
typedef bit<8>  protocol_t;
typedef bit<3>  flags_t;

typedef bit<32> entropyTerm_t;
typedef bit<32> pktNum_t;
typedef bit<8>  alarm_t;
typedef bit<8>  drState_t;
typedef bit<32> entropy_t;
typedef bit<32> EWMA_t;
typedef bit<32> EWMMD_t;

const etherType_t TYPE_DDOS     = 16w0x6605;
const etherType_t TYPE_IPV4     = 16w0x0800;
const etherType_t TYPE_ARP      = 16w0x0806;  // 地址解析协议
const etherType_t TYPE_VLAN     = 16w0x8100;
const etherType_t TYPE_IPV6     = 16w0x86DD;
const etherType_t TYPE_LLDP     = 16w0x88CC;  // 链路层发现协议
const etherType_t TYPE_PROFINET = 16w0x8892;  // 工业以太网

const dscp_t DSCP_DEFAULT = 6w0b000000;  // 普通优先级
const dscp_t DSCP_CS1     = 6w0b001000;
const dscp_t DSCP_AF11    = 6w0b001010;
const dscp_t DSCP_EF      = 6w0b101110;

const ecn_t ECN_ZERO = 2w0b00;
const ecn_t ECN_CT   = 2w0b10;
const ecn_t ECN_CE   = 2w0b11;

const protocol_t PROTO_ICMP   = 8w0x01;
const protocol_t PROTO_IGMP   = 8w0x02;
const protocol_t PROTO_TCP    = 8w0x06;
const protocol_t PROTO_UDP    = 8w0x11;
const protocol_t PROTO_GRE    = 8w0x2F;
const protocol_t PROTO_OSPF   = 8w0x59;
const protocol_t PROTO_CUSTOM = 8w0xFC;
const protocol_t PROTO_INT    = 8w0xFD;

const flags_t FLAGS_DF = 3w0b010;  // 不允许分片
const flags_t FLAGS_MF = 3w0b001;  // 有后续分片
const flags_t FLAGS_LF = 3w0b000;  // 不分片（最后一段）

// 防御就绪状态
const drState_t DR_SAFE     = 0
const drState_t DR_ACTIVE   = 1
const drState_t DR_COOLDOWN = 2

header ethernet_t {
    macAddr_t   dstAddr;
    macAddr_t   srcAddr;
    etherType_t etherType;
}

header ddos_t {
    pktNum_t    pktNum;      // 观察窗口内的数据包数量（始终等于 m）
    entropy_t   srcEntropy;  // 源 IP 地址的最后一个观察窗口熵（按 2**4 缩放）
    EWMA_t      srcEWMA;
    EWMMD_t     srcEWMMD;
    entropy_t   dstEntropy;
    EWMA_t      dstEWMA;
    EWMMD_t     dstEWMMD;
    alarm_t     alarm;
    drState_t   drState;     // 设置为 0x01 表示检测到 DDoS 攻击
    etherType_t etherType;   // 表示后续报头的 EtherType，从以太网报头复制
}

header ipv4_t {
    bit<4>     version;
    bit<4>     ihl;
    dscp_t     dscp;
    ecn_t      ecn;
    bit<16>    totalLen;
    bit<16>    identification;
    flags_t    flags;
    bit<13>    fragOffset;
    bit<8>     ttl;
    protocol_t protocol;
    bit<16>    hdrChecksum;
    ip4Addr_t  srcAddr;
    ip4Addr_t  dstAddr;
}

struct headers {
    ethernet_t ethernet;
    ddos_t     ddos;
    ipv4_t     ipv4;
}

struct metadata {
    int<32>       ipCount;
    entropyTerm_t entropyTerm;
    pktNum_t      pktNum;
    entropy_t     srcEntropy;
    EWMA_t        srcEWMA;
    EWMMD_t       srcEWMMD;
    entropy_t     dstEntropy;
    EWMA_t        dstEWMA;
    EWMMD_t       dstEWMMD;
    alarm_t       alarm;
    drState_t     drState;
}

#endif  /* _HEADERS_P4_ */
