#ifndef _GLOBAL_P4_
#define _GLOBAL_P4_

#include <core.p4>
#include <v1model.p4>

#define ALARM_SESSION 321
#define CS_WIDTH 1280

// 数据包分类
#define LEGITIMATE 0
#define MALICIOUS 1

typedef bit<8>  wid_t
typedef bit<32> instanceType_t

typedef bit<8>        ID_t;
typedef bit<64>       packetCount_t;
typedef bit<48>       timestamp_t;
typedef bit<8>        tokenCalculateStrategy_t;
typedef bit<8>        controlBehavior_t;
typedef packetCount_t threshold_t;
typedef timestamp_t   warmUpPeriodSec_t;
typedef bit<16>       warmUpColdFactor_t;
typedef timestamp_t   statIntervalInMs_t;

const instanceType_t INSTANCE_TYPE_NORMAL = 0;
const instanceType_t INSTANCE_TYPE_CLONE  = 1;

const tokenCalculateStrategy_t STRATEGY_DIRECT  = 1;
const tokenCalculateStrategy_t STRATEGY_WARM_UP = 2;

const controlBehavior_t BEHAVIOR_REJECT     = 1;
const controlBehavior_t BEHAVIOR_THROTTLING = 2;

register<packetCount_t, ID_t>(2 << 8) passed;
register<packetCount_t, ID_t>(2 << 8) blocked;
register<timestamp_t, ID_t>(2 << 8)   timestamp;

register<threshold_t, ID_t>(2 << 8) warm_up_threshold;         // 预热模式下的真实阈值
register<timestamp_t, ID_t>(2 << 8) warm_up_update_timestamp;  // 更新预热阈值的时间
register<timestamp_t, ID_t>(2 << 8) warm_up_ms_per_threshold;  // 预热/冷启动后每多少微秒后增加一个阈值

// 观察窗口参数
register<bit<5>>(1) log2_m;
register<bit<32>>(1) training_len;

// 观察窗口控制
register<bit<32>>(1) ow_counter;
register<bit<32>>(1) pkt_counter;

// 缓解阈值
register<int<32>>(1) mitigation_threshold;


/**
 * 计数草图声明
 *
 * 有六个计数草图：
 *     `CS_Src_Curr`, `CS_Src_Last`, `CS_Src_Safe`,
 *     `CS_Dst_Curr`, `CS_Dst_Last`, `CS_Dst_Safe`
 *
 * “Src” 和 “Dst” 表示草图是否近似源或目标 IP 地址的计数
 * “Curr”、“Last” 和 “Safe” 表示草图引用的观察窗口类型
 *
 * 由于 P4 不提供矩阵或记录，因此每个草图行需要两个草图，
 * 一个用于计数器，一个用于观察窗口 ID 注释。
 */

// CS_Src_Curr (源 IP) (当前 OW)
// 计数器
register<int<32>>(CS_WIDTH) cs_src_curr_1;
register<int<32>>(CS_WIDTH) cs_src_curr_2;
register<int<32>>(CS_WIDTH) cs_src_curr_3;
register<int<32>>(CS_WIDTH) cs_src_curr_4;
// 注释
register<bit<8>>(CS_WIDTH) cs_src_curr_1_wid;
register<bit<8>>(CS_WIDTH) cs_src_curr_2_wid;
register<bit<8>>(CS_WIDTH) cs_src_curr_3_wid;
register<bit<8>>(CS_WIDTH) cs_src_curr_4_wid;

// CS_Dst_Curr (目标 IP) (当前 OW)
// 计数器
register<int<32>>(CS_WIDTH) cs_dst_curr_1;
register<int<32>>(CS_WIDTH) cs_dst_curr_2;
register<int<32>>(CS_WIDTH) cs_dst_curr_3;
register<int<32>>(CS_WIDTH) cs_dst_curr_4;
// 注释
register<bit<8>>(CS_WIDTH) cs_dst_curr_1_wid;
register<bit<8>>(CS_WIDTH) cs_dst_curr_2_wid;
register<bit<8>>(CS_WIDTH) cs_dst_curr_3_wid;
register<bit<8>>(CS_WIDTH) cs_dst_curr_4_wid;

// CS_Src_Last (源 IP) (Last OW)
register<int<32>>(CS_WIDTH) cs_src_last_1;
register<int<32>>(CS_WIDTH) cs_src_last_2;
register<int<32>>(CS_WIDTH) cs_src_last_3;
register<int<32>>(CS_WIDTH) cs_src_last_4;

// CS_Dst_Last (目标 IP) (Last OW)
register<int<32>>(CS_WIDTH) cs_dst_last_1;
register<int<32>>(CS_WIDTH) cs_dst_last_2;
register<int<32>>(CS_WIDTH) cs_dst_last_3;
register<int<32>>(CS_WIDTH) cs_dst_last_4;

// CS_Src_Safe (源 IP) (Safe OW)
register<int<32>>(CS_WIDTH) cs_src_safe_1;
register<int<32>>(CS_WIDTH) cs_src_safe_2;
register<int<32>>(CS_WIDTH) cs_src_safe_3;
register<int<32>>(CS_WIDTH) cs_src_safe_4;

// CS_Dst_Safe (目标 IP) (Safe OW)
register<int<32>>(CS_WIDTH) cs_dst_safe_1;
register<int<32>>(CS_WIDTH) cs_dst_safe_2;
register<int<32>>(CS_WIDTH) cs_dst_safe_3;
register<int<32>>(CS_WIDTH) cs_dst_safe_4;

// 熵范数 - 定点表示：28 个整数位，4 个小数位
register<bit<32>>(1) src_S;
register<bit<32>>(1) dst_S;

// 熵 EWMA 和 EWMMD - 定点表示：14 个整数位，18 个小数位
register<bit<32>>(1) src_ewma;
register<bit<32>>(1) src_ewmmd;
register<bit<32>>(1) dst_ewma;
register<bit<32>>(1) dst_ewmmd;

// 平滑系数和敏感度系数
register<bit<8>>(1) alpha;  // 定点表示：0 个整数位，8 个小数位
register<bit<8>>(1) k;      // 定点表示：5 个整数位，3 个小数位

// 防御就绪状态
register<bit<8>>(1) dr_state;


struct reported_data {
    packetCount_t passed;
    packetCount_t blocked;
}

struct warm_up_data {
    threshold_t threshold;
    packetCount_t passed;
    packetCount_t blocked;
}


const bit<32> HASH_BASE = 32w0x0
const bit<32> HASH_MAX  = 32w0xffffffff

action cs_hash(in  ip4Addr_t ipv4_addr,
               out bit<32>   h1,
               out bit<32>   h2,
               out bit<32>   h3,
               out bit<32>   h4) {
    hash(h1, HashAlgorithm.h1, HASH_BASE, { ipv4_addr }, HASH_MAX);
    hash(h2, HashAlgorithm.h2, HASH_BASE, { ipv4_addr }, HASH_MAX);
    hash(h3, HashAlgorithm.h3, HASH_BASE, { ipv4_addr }, HASH_MAX);
    hash(h4, HashAlgorithm.h4, HASH_BASE, { ipv4_addr }, HASH_MAX);
}

action cs_ghash(in  ip4Addr_t ipv4_addr,
                out int<32>   g1,
                out int<32>   g2,
                out int<32>   g3,
                out int<32>   g4) {
    hash(g1, HashAlgorithm.g1, HASH_BASE, { ipv4_addr }, HASH_MAX);
    hash(g2, HashAlgorithm.g2, HASH_BASE, { ipv4_addr }, HASH_MAX);
    hash(g3, HashAlgorithm.g3, HASH_BASE, { ipv4_addr }, HASH_MAX);
    hash(g4, HashAlgorithm.g4, HASH_BASE, { ipv4_addr }, HASH_MAX);

    // 由于 ghash 输出 0 或 1，必须将 0 映射到 -1
    g1 = g1 << 1 - 1;
    g2 = g2 << 1 - 1;
    g3 = g3 << 1 - 1;
    g4 = g4 << 1 - 1;
}

action median(in  int<32> x1,
              in  int<32> x2,
              in  int<32> x3,
              in  int<32> x4,
              out int<32> y) {
    // 中值运算符硬编码
    if ((x1 <= x2 && x1 <= x3 && x1 <= x4 && x2 >= x3 && x2 >= x4) ||
        (x2 <= x1 && x2 <= x3 && x2 <= x4 && x1 >= x3 && x1 >= x4)) {
        y = x3 + x4;
    } else if ((x1 <= x2 && x1 <= x3 && x1 <= x4 && x3 >= x2 && x3 >= x4) ||
               (x3 <= x1 && x3 <= x2 && x3 <= x4 && x1 >= x2 && x1 >= x4)) {
        y = x2 + x4;
    } else if ((x1 <= x2 && x1 <= x3 && x1 <= x4 && x4 >= x2 && x4 >= x3) ||
               (x4 <= x1 && x4 <= x2 && x4 <= x3 && x1 >= x2 && x1 >= x3)) {
        y = x2 + x3;
    } else if ((x2 <= x1 && x2 <= x3 && x2 <= x4 && x3 >= x1 && x3 >= x4) ||
               (x3 <= x1 && x3 <= x2 && x3 <= x4 && x2 >= x1 && x2 >= x4)) {
        y = x1 + x4;
    } else if ((x2 <= x1 && x2 <= x3 && x2 <= x4 && x4 >= x1 && x4 >= x3) ||
               (x4 <= x1 && x4 <= x2 && x4 <= x3 && x2 >= x1 && x2 >= x3)) {
        y = x1 + x3;
    } else {
        y = x1 + x2;
    }
    y = y >> 1;
}

#endif  /* _GLOBAL_P4_ */
