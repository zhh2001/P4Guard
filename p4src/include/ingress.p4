#ifndef _INGRESS_P4_
#define _INGRESS_P4_

#include <core.p4>
#include <v1model.p4>

#include "global.p4"
#include "headers.p4"

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // 在 SAFE 缓解状态下，此表适用于所有数据包。
    // 在 ACTIVE 和 COOLDOWN 状态下，此表仅适用于被视为合法的数据包。
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // 在 ACTIVE 和 COOLDOWN 缓解状态下，此表仅适用于被视为 MALICIOUS 的数据包
    table ipv4_dpi_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action get_entropy_term(entropyTerm_t entropy_term) {
        meta.entropyTerm = entropy_term;
    }

    table src_entropy_term {
        key = {
            meta.ipCount: lpm;
        }
        actions = {
            get_entropy_term;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = get_entropy_term(0);
    }

    table dst_entropy_term {
        key = {
            meta.ipCount: lpm;
        }
        actions = {
            get_entropy_term;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = get_entropy_term(0);
    }

    apply {
        if (hdr.ipv4.isValid()) {
            // 从寄存器中获取观察窗口编号
            bit<32> current_wid;
            ow_counter.read(current_wid, 0);

            // 从寄存器中获取防御准备状态
            drState_t dr_state_aux;
            dr_state.read(dr_state_aux, 0);

            // 从寄存器中获取缓解阈值
            int<32> mitigation_threshold_aux;
            mitigation_threshold.read(mitigation_threshold_aux, 0);

            // 用于频率变化分析的变量
            int<32> f_src_last;
            int<32> f_src_safe;
            int<32> f_dst_last;
            int<32> f_dst_safe;
            int<32> v_src;
            int<32> v_dst;
            int<32> v;

            // -------------------------------- 源地址频率和熵范数估计的开始 --------------------------------

            // 获取所有行的列 ID
            bit<32> src_hash_1;
            bit<32> src_hash_2;
            bit<32> src_hash_3;
            bit<32> src_hash_4;
            cs_hash(hdr.ipv4.src_addr, src_hash_1, src_hash_2, src_hash_3, src_hash_4);

            // 确定是否增加或减少计数器
            int<32> src_ghash_1;
            int<32> src_ghash_2;
            int<32> src_ghash_3;
            int<32> src_ghash_4;
            cs_ghash(hdr.ipv4.src_addr, src_ghash_1, src_ghash_2, src_ghash_3, src_ghash_4);

            // 估算源地址的频率

            // 用于计数器和注释的变量
            // 用于频率近似和熵估计：
            int<32> src_curr_1;
            int<32> src_curr_2;
            int<32> src_curr_3;
            int<32> src_curr_4;
            wid_t   src_curr_1_wid;
            wid_t   src_curr_2_wid;
            wid_t   src_curr_3_wid;
            wid_t   src_curr_4_wid;
            // 用于频率变化分析：
            int<32> src_last_1;
            int<32> src_last_2;
            int<32> src_last_3;
            int<32> src_last_4;
            int<32> src_safe_1;
            int<32> src_safe_2;
            int<32> src_safe_3;
            int<32> src_safe_4;

            // 读取计数器和注释
            cs_src_curr_1.read(src_curr_1, src_hash_1);          // 读取当前计数器
            cs_src_curr_2.read(src_curr_2, src_hash_2);          // 读取当前计数器
            cs_src_curr_3.read(src_curr_3, src_hash_3);          // 读取当前计数器
            cs_src_curr_4.read(src_curr_4, src_hash_4);          // 读取当前计数器
            cs_src_curr_1_wid.read(src_curr_1_wid, src_hash_1);  // 读取当前注释
            cs_src_curr_2_wid.read(src_curr_2_wid, src_hash_2);  // 读取当前注释
            cs_src_curr_3_wid.read(src_curr_3_wid, src_hash_3);  // 读取当前注释
            cs_src_curr_4_wid.read(src_curr_4_wid, src_hash_4);  // 读取当前注释
            cs_src_last_1.read(src_last_1, src_hash_1);          // 读取Wlast计数器
            cs_src_last_2.read(src_last_2, src_hash_2);          // 读取Wlast计数器
            cs_src_last_3.read(src_last_3, src_hash_3);          // 读取Wlast计数器
            cs_src_last_4.read(src_last_4, src_hash_4);          // 读取Wlast计数器
            cs_src_safe_1.read(src_safe_1, src_hash_1);          // 读取 Wsafe 计数器
            cs_src_safe_2.read(src_safe_2, src_hash_2);          // 读取 Wsafe 计数器
            cs_src_safe_3.read(src_safe_3, src_hash_3);          // 读取 Wsafe 计数器
            cs_src_safe_4.read(src_safe_4, src_hash_4);          // 读取 Wsafe 计数器

            // 执行计数器重置和复制
            // 在一个 OW 中，每个地址的计数器重置和复制必须恰好发生一次
            // 通过检查窗口 ID 注释 `src_curr_d_wid != current_wid` 来确保这一点
            // 仅当该地址在 OW 中第一次出现时，测试才会成立

            // 此时，还将执行频率变化分析

            // 第 1 行估计
            if (src_curr_1_wid != current_wid[7:0]) {                       // 窗口已更改
                if (current_wid[7:0] > 1) {                                 // 这不是第一个窗口
                    if (dr_state_aux == DR_SAFE) {                          // DR 状态为 SAFE
                        src_safe_1 = src_last_1;                            // 将 Wlast 计数器复制到 Wsafe
                        cs_src_safe_1.write(src_hash_1, src_safe_1);        // Write back.
                    }
                }
                src_last_1 = src_curr_1;                                    // 将 Wcurr 计数器复制到 Wlast
                cs_src_last_1.write(src_hash_1, src_last_1);                // Write back.
                src_curr_1 = 0;                                             // 重置计数器
                cs_src_curr_1_wid.write(src_hash_1, current_wid[7:0]);      // Update the annotation.
            }

            // 第 2 行估计
            if (src_curr_2_wid != current_wid[7:0]) {                       // 窗口已更改
                if (current_wid[7:0] > 1) {                                 // 这不是第一个窗口
                    if (dr_state_aux == DR_SAFE) {                          // DR 状态为 SAFE
                        src_safe_2 = src_last_2;                            // 将 Wlast 计数器复制到 Wsafe
                        cs_src_safe_2.write(src_hash_2, src_safe_2);        // Write back.
                    }
                }
                src_last_2 = src_curr_2;                                    // 将 Wcurr 计数器复制到 Wlast
                cs_src_last_2.write(src_hash_2, src_last_2);                // Write back.
                src_curr_2 = 0;                                             // 重置计数器
                cs_src_curr_2_wid.write(src_hash_2, current_wid[7:0]);      // Update the annotation.
            }

            // 第 3 行估计
            if (src_curr_3_wid != current_wid[7:0]) {                       // 窗口已更改
                if (current_wid[7:0] > 1) {                                 // 这不是第一个窗口
                    if (dr_state_aux == DR_SAFE) {                          // DR 状态为 SAFE
                        src_safe_3 = src_last_3;                            // 将 Wlast 计数器复制到 Wsafe
                        cs_src_safe_3.write(src_hash_3, src_safe_3);        // Write back.
                    }
                }
                src_last_3 = src_curr_3;                                    // 将 Wcurr 计数器复制到 Wlast
                cs_src_last_3.write(src_hash_3, src_last_3);                // Write back.
                src_curr_3 = 0;                                             // 重置计数器
                cs_src_curr_3_wid.write(src_hash_3, current_wid[7:0]);      // Update the annotation.
            }

            // 估算第 4 行
            if (src_curr_4_wid != current_wid[7:0]) {                       // The window has changed.
                if (current_wid[7:0] > 1) {                                 // 这不是第一个窗口
                    if (dr_state_aux == DR_SAFE) {                          // DR 状态为 SAFE
                        src_safe_4 = src_last_4;                            // 将 Wlast 计数器复制到 Wsafe
                        cs_src_safe_4.write(src_hash_4, src_safe_4);        // Write back.
                    }
                }
                src_last_4 = src_curr_4;
                src_curr_4 = 0;
                cs_src_last_4.write(src_hash_4, src_last_4);
                cs_src_curr_4_wid.write(src_hash_4, current_wid[7:0]);
            }


            // 更新计数器
            src_curr_1 = src_curr_1 + src_ghash_1;
            src_curr_2 = src_curr_2 + src_ghash_2;
            src_curr_3 = src_curr_3 + src_ghash_3;
            src_curr_4 = src_curr_4 + src_ghash_4;

            // 将计数器写回草图
            cs_src_curr_1.write(src_hash_1, src_curr_1);
            cs_src_curr_2.write(src_hash_2, src_curr_2);
            cs_src_curr_3.write(src_hash_3, src_curr_3);
            cs_src_curr_4.write(src_hash_4, src_curr_4);

            // ghash 和计数器符号相同；将计算绝对值
            src_curr_1 = src_curr_1 * src_ghash_1;
            src_curr_2 = src_curr_2 * src_ghash_2;
            src_curr_3 = src_curr_3 * src_ghash_3;
            src_curr_4 = src_curr_4 * src_ghash_4;

            // 此时已经更新了 `src_curr_1`、`src_curr_2`、`src_curr_3` 和 `src_curr_4` 中的计数器

            // 计算 Sketch 源 IP 频率估计值：将其存储在 `meta.ipCount` 中
            median(src_curr_1, src_curr_2, src_curr_3, src_curr_4, meta.ipCount);

            // LPM 表查找
            // 副作用：meta.entropyTerm 被更新
            if (meta.ipCount > 0) {              // 这样可以避免在参数为零时执行查找
                src_entropy_term.apply();
            } else {
                meta.entropyTerm = 0;
            }

            // 此时 `meta.entropyTerm` 的值已增加

            // 源熵范数更新
            bit<32> src_S_aux;
            src_S.read(src_S_aux, 0);
            src_S_aux = src_S_aux + meta.entropyTerm;
            src_S.write(0, src_S_aux);

            // -------------------------------- 源地址频率和熵范数估计的结束 --------------------------------

            // -------------------------------- 目标地址频率和熵范数估计的起始位置 --------------------------------

            // 获取所有行的列 ID
            bit<32> dst_hash_1;
            bit<32> dst_hash_2;
            bit<32> dst_hash_3;
            bit<32> dst_hash_4;
            cs_hash(hdr.ipv4.dstAddr, dst_hash_1, dst_hash_2, dst_hash_3, dst_hash_4);

            // 确定是否增加或减少计数器
            int<32> dst_ghash_1;
            int<32> dst_ghash_2;
            int<32> dst_ghash_3;
            int<32> dst_ghash_4;
            cs_ghash(hdr.ipv4.dstAddr, dst_ghash_1, dst_ghash_2, dst_ghash_3, dst_ghash_4);

            // 估算目标地址的频率

            // 用于计数器和注释的变量
            // 用于频率近似和熵估计：
            int<32> dst_curr_1;
            int<32> dst_curr_2;
            int<32> dst_curr_3;
            int<32> dst_curr_4;
            wid_t   dst_curr_1_wid;
            wid_t   dst_curr_2_wid;
            wid_t   dst_curr_3_wid;
            wid_t   dst_curr_4_wid;
            // 用于频率变化分析：
            int<32> dst_last_1;
            int<32> dst_last_2;
            int<32> dst_last_3;
            int<32> dst_last_4;
            int<32> dst_safe_1;
            int<32> dst_safe_2;
            int<32> dst_safe_3;
            int<32> dst_safe_4;

            // 读取计数器和注释
            cs_dst_curr_1.read(dst_curr_1, dst_hash_1);          // Read current counter.
            cs_dst_curr_2.read(dst_curr_2, dst_hash_2);
            cs_dst_curr_3.read(dst_curr_3, dst_hash_3);
            cs_dst_curr_4.read(dst_curr_4, dst_hash_4);
            cs_dst_curr_1_wid.read(dst_curr_1_wid, dst_hash_1);  // Read current annotation.
            cs_dst_curr_2_wid.read(dst_curr_2_wid, dst_hash_2);
            cs_dst_curr_3_wid.read(dst_curr_3_wid, dst_hash_3);
            cs_dst_curr_4_wid.read(dst_curr_4_wid, dst_hash_4);
            cs_dst_last_1.read(dst_last_1, dst_hash_1);          // Read Wlast counter.
            cs_dst_last_2.read(dst_last_2, dst_hash_2);
            cs_dst_last_3.read(dst_last_3, dst_hash_3);
            cs_dst_last_4.read(dst_last_4, dst_hash_4);
            cs_dst_safe_1.read(dst_safe_1, dst_hash_1);          // Read Wsafe counter.
            cs_dst_safe_2.read(dst_safe_2, dst_hash_2);
            cs_dst_safe_3.read(dst_safe_3, dst_hash_3);
            cs_dst_safe_4.read(dst_safe_4, dst_hash_4);

           // Row 1 Estimate
            if (dst_curr_1_wid != current_wid[7:0]) {                       // The window has changed.
                if (current_wid[7:0] > 1) {                                 // 这不是第一个窗口
                    if (dr_state_aux == DR_SAFE) {                          // DR 状态为 SAFE
                        dst_safe_1 = dst_last_1;                            // 将 Wlast 计数器复制到 Wsafe
                        cs_dst_safe_1.write(dst_hash_1, dst_safe_1);        // Write back.
                    }
                }
                dst_last_1 = dst_curr_1;                                    // 将 Wcurr 计数器复制到 Wlast
                dst_curr_1 = 0;                                             // 重置计数器
                cs_dst_last_1.write(dst_hash_1, dst_last_1);                // Write back.
                cs_dst_curr_1_wid.write(dst_hash_1, current_wid[7:0]);      // Update the annotation.
            }

            // Row 2 Estimate
            if (dst_curr_2_wid != current_wid[7:0]) {                       // The window has changed.
                if (current_wid[7:0] > 1) {                                 // 这不是第一个窗口
                    if (dr_state_aux == DR_SAFE) {                          // DR 状态为 SAFE
                        dst_safe_2 = dst_last_2;                            // 将 Wlast 计数器复制到 Wsafe
                        cs_dst_safe_2.write(dst_hash_2, dst_safe_2);        // Write back.
                    }
                }
                dst_last_2 = dst_curr_2;                                    // 将 Wcurr 计数器复制到 Wlast
                dst_curr_2 = 0;                                             // 重置计数器
                cs_dst_last_2.write(dst_hash_2, dst_last_2);                // Write back.
                cs_dst_curr_2_wid.write(dst_hash_2, current_wid[7:0]);      // Update the annotation.
            }

            // Row 3 Estimate
            if (dst_curr_3_wid != current_wid[7:0]) {                       // The window has changed.
                if (current_wid[7:0] > 1) {                                 // 这不是第一个窗口
                    if (dr_state_aux == DR_SAFE) {                          // DR 状态为 SAFE
                        dst_safe_3 = dst_last_3;                            // 将 Wlast 计数器复制到 Wsafe
                        cs_dst_safe_3.write(dst_hash_3, dst_safe_3);        // Write back.
                    }
                }
                dst_last_3 = dst_curr_3;                                    // 将 Wcurr 计数器复制到 Wlast
                dst_curr_3 = 0;                                             // 重置计数器
                cs_dst_last_3.write(dst_hash_3, dst_last_3);                // Write back.
                cs_dst_curr_3_wid.write(dst_hash_3, current_wid[7:0]);      // Update the annotation.
            }

            // Row 4 Estimate
            if (dst_curr_4_wid != current_wid[7:0]) {                       // The window has changed.
                if (current_wid[7:0] > 1) {                                 // 这不是第一个窗口
                    if (dr_state_aux == DR_SAFE) {                          // DR 状态为 SAFE
                        dst_safe_4 = dst_last_4;                            // 将 Wlast 计数器复制到 Wsafe
                        cs_dst_safe_4.write(dst_hash_4, dst_safe_4);        // Write back.
                    }
                }
                dst_last_4 = dst_curr_4;                                    // 将 Wcurr 计数器复制到 Wlast
                dst_curr_4 = 0;                                             // 重置计数器
                cs_dst_last_4.write(dst_hash_4, dst_last_4);                // Write back.
                cs_dst_curr_4_wid.write(dst_hash_4, current_wid[7:0]);      // Update the annotation.
            }

            // 更新计数器
            dst_curr_1 = dst_curr_1 + dst_ghash_1;  // 更新计数器
            dst_curr_2 = dst_curr_2 + dst_ghash_2;
            dst_curr_3 = dst_curr_3 + dst_ghash_3;
            dst_curr_4 = dst_curr_4 + dst_ghash_4;

            cs_dst_curr_1.write(dst_hash_1, dst_curr_1);
            cs_dst_curr_2.write(dst_hash_2, dst_curr_2);
            cs_dst_curr_3.write(dst_hash_3, dst_curr_3);
            cs_dst_curr_4.write(dst_hash_4, dst_curr_4);

            dst_curr_1 = dst_curr_1 * dst_ghash_1;
            dst_curr_2 = dst_curr_2 * dst_ghash_2;
            dst_curr_3 = dst_curr_3 * dst_ghash_3;
            dst_curr_4 = dst_curr_4 * dst_ghash_4;

            // 此时已经更新了 `dst_curr_1`、`dst_curr_2`、`dst_curr_3` 和 `dst_curr_4` 中的计数器

            // 计数 Sketch 目标 IP 频率估算
            median(
                dst_curr_1,
                dst_curr_2,
                dst_curr_3,
                dst_curr_4,
                meta.ipCount
            );

            // LPM 表查找
            // 副作用：`meta.entropyTerm` 已更新
            if (meta.ipCount <= 0) {
                meta.entropyTerm = 0;
            } else {
                dst_entropy_term.apply();
            }
            // 此时，`meta.entropyTerm` 的值已增加

            bit<32> dst_S_aux;
            dst_S.read(dst_S_aux, 0);
            dst_S_aux = dst_S_aux + meta.entropyTerm;
            dst_S.write(0, dst_S_aux);

            // -------------------------------- 目的地址频率和熵范数估计的结束 --------------------------------

            // -------------------------------- 异常检测的开始 --------------------------------
            // Step 2: If the OW has ended, estimate the entropies.
            // Step 3: If we detect an entropy anomaly, signal this condition. Otherwise, just update the moving averages.

            // 步骤 1：检查观察窗口是否结束

            bit<32> m;                         // 观察窗口的大小
            bit<5> log2_m_aux;
            log2_m.read(log2_m_aux, 0);
            m = 32w1 << log2_m_aux;            // m = 2**log2(m)
            pkt_counter.read(meta.pktNum, 0);
            meta.pktNum = meta.pktNum + 1;

            if (meta.pktNum != m) {
                pkt_counter.write(0, meta.pktNum);
            } else {
                current_wid = current_wid + 1;
                ow_counter.write(0, current_wid);

                // 步骤 2：如果观察窗口已结束，则估算熵

                // 计算 Ĥ = log2(m) - Ŝ/m .
                // 由于P4流水线没有实现除法，因此对于正 m，我们可以采用公式 1/m = 2^(-log2(m))
                // 假设 m 是 2 的整数幂，并且我们已经知道 log2(m)，除法就变成了右移 log2(m) 位
                // 因此，Ĥ = log2(m) - Ŝ/m = log2(m) - Ŝ * 2^(-log2(m)).
                meta.srcEntropy = ((entropy_t)log2_m_aux << 4) - (src_S_aux >> log2_m_aux);
                meta.dstEntropy = ((entropy_t)log2_m_aux << 4) - (dst_S_aux >> log2_m_aux);

                // 读取移动平均线和偏差
                src_ewma.read(meta.srcEWMA, 0);
                src_ewmmd.read(meta.srcEWMMD, 0);
                dst_ewma.read(meta.dstEWMA, 0);
                dst_ewmmd.read(meta.dstEWMMD, 0);

                if (current_wid == 1) {
                    meta.srcEWMA = meta.srcEntropy << 14;  // 使用第一个估算出的熵初始化平均值。平均值有 18 位小数
                    meta.dstEWMA = meta.dstEntropy << 14;
                    meta.srcEWMMD = 0;
                    meta.dstEWMMD = 0;

                    } else {
                    meta.alarm = 0;

                    // ====== 步骤 3：如果检测到熵异常，则发出信号。否则，仅更新移动平均值

                    bit<32> training_len_aux;
                    training_len.read(training_len_aux, 0);
                    if (current_wid > training_len_aux) {
                        bit<8> k_aux;
                        k.read(k_aux, 0);

                        bit<32> src_thresh;
                        src_thresh = meta.srcEWMA + ((bit<32>)k_aux * meta.srcEWMMD >> 3);

                        bit<32> dst_thresh;
                        dst_thresh = meta.dstEWMA - ((bit<32>)k_aux * meta.dstEWMMD >> 3);

                        if ((meta.srcEntropy << 14) > src_thresh || (meta.dstEntropy << 14) < dst_thresh) {
                            dr_state_aux = DR_ACTIVE;
                            dr_state.write(0, dr_state_aux);
                            meta.drState = dr_state_aux;
                            meta.alarm = 1;
                        }

                    }

                    if (meta.alarm == 0) {
                        bit<8> alpha_aux;
                        alpha.read(alpha_aux, 0);

                        // 定点对齐：
                        //   Alpha：8 位小数；熵：4 位小数。EWMA 和 EWMMD：18 位小数。
                        //   Alpha * Entropy：8 + 4 = 12 位；左移 6 位得到 18 位。
                        //   Alpha * EWMx：8 + 18 = 26 位；右移 8 位得到 18 位。

                        meta.srcEWMA = (((EWMA_t)alpha_aux * meta.srcEntropy) << 6) + (((0x00000100 - (EWMA_t)alpha_aux) * meta.srcEWMA) >> 8);
                        meta.dstEWMA = (((EWMA_t)alpha_aux * meta.dstEntropy) << 6) + (((0x00000100 - (EWMA_t)alpha_aux) * meta.dstEWMA) >> 8);

                        if ((meta.srcEntropy << 14) < meta.srcEWMA) {
                            meta.srcEWMMD = (((EWMMD_t)alpha_aux * (meta.srcEWMA - (meta.srcEntropy << 14))) >> 8) + (((0x00000100 - (EWMMD_t)alpha_aux) * meta.srcEWMMD) >> 8);
                        } else {
                            meta.srcEWMMD = (((EWMMD_t)alpha_aux * ((meta.srcEntropy << 14) - meta.srcEWMA)) >> 8) + (((0x00000100 - (EWMMD_t)alpha_aux) * meta.srcEWMMD) >> 8);
                        }

                        if ((meta.dst_entropy << 14) < meta.dstEWMA) {
                            meta.dstEWMMD = (((EWMMD_t)alpha_aux * (meta.dstEWMA - (meta.dstEntropy << 14))) >> 8) + (((0x00000100 - (EWMMD_t)alpha_aux) * meta.dstEWMMD) >> 8);
                        } else {
                            meta.dstEWMMD = (((EWMMD_t)alpha_aux * ((meta.dstEntropy << 14) - meta.dstEWMA)) >> 8) + (((0x00000100 - (EWMMD_t)alpha_aux) * meta.dstEWMMD) >> 8);
                        }
                    }

                    // ====== 步骤 3 结束

                }

                // ====== 步骤 2 结束

                // 下一个观察窗口的准备：

                src_ewma.write(0, meta.srcEWMA);
                dst_ewma.write(0, meta.dstEWMA);
                src_ewmmd.write(0, meta.srcEWMMD);
                dst_ewmmd.write(0, meta.dstEWMMD);

                // 重置数据包计数器和熵项
                src_S.write(0, 0);
                dst_S.write(0, 0);
                pkt_counter.write(0, 0);

                // 检查是否应该重置防御就绪状态
                if (meta.alarm == 0 && dr_state_aux == DR_ACTIVE) {
                    dr_state_aux = DR_SAFE;
                    dr_state.write(0, dr_state_aux);
                }

                clone3(
                    CloneType.I2E,
                    ALARM_SESSION,
                    {
                        meta.pktNum,
                        meta.srcEntropy,
                        meta.srcEWMA,
                        meta.srcEWMMD,
                        meta.dstEntropy,
                        meta.dstEWMA,
                        meta.dstEWMMD,
                        meta.alarm,
                        meta.drState
                    }
                );
            }

            // ====== 步骤 1 结束

            bit<1> classification;
            classification = LEGITIMATE;  // 默认情况下，将所有数据包归类为合法数据包

            if (dr_state_aux == DR_ACTIVE) {  // 缓解已启用

                // 频率变化分析

                // 获取 Wlast 处源地址的估计计数器
                src_last_1 = src_last_1 * src_ghash_1;
                src_last_2 = src_last_2 * src_ghash_2;
                src_last_3 = src_last_3 * src_ghash_3;
                src_last_4 = src_last_4 * src_ghash_4;
                median(
                    src_last_1,
                    src_last_2,
                    src_last_3,
                    src_last_4,
                    f_src_last
                );

                // 获取 Wsafe 处源地址的估计计数器
                src_safe_1 = src_safe_1 * src_ghash_1;
                src_safe_2 = src_safe_2 * src_ghash_2;
                src_safe_3 = src_safe_3 * src_ghash_3;
                src_safe_4 = src_safe_4 * src_ghash_4;
                median(
                    src_safe_1,
                    src_safe_2,
                    src_safe_3,
                    src_safe_4,
                    f_src_safe
                );

                // 获取 Wlast 处目标地址的估计计数器
                dst_last_1 = dst_last_1 * dst_ghash_1;
                dst_last_2 = dst_last_2 * dst_ghash_2;
                dst_last_3 = dst_last_3 * dst_ghash_3;
                dst_last_4 = dst_last_4 * dst_ghash_4;
                median(
                    dst_last_1,
                    dst_last_2,
                    dst_last_3,
                    dst_last_4,
                    f_dst_last
                );

                // 获取 Wsafe 处目标地址的预估计数器
                dst_safe_1 = dst_safe_1 * dst_ghash_1;
                dst_safe_2 = dst_safe_2 * dst_ghash_2;
                dst_safe_3 = dst_safe_3 * dst_ghash_3;
                dst_safe_4 = dst_safe_4 * dst_ghash_4;
                median(
                    dst_safe_1,
                    dst_safe_2,
                    dst_safe_3,
                    dst_safe_4,
                    f_dst_safe
                );

                // 计算频率变化
                v_src = f_src_last - f_src_safe;
                v_dst = f_dst_last - f_dst_safe;
                v = v_dst - v_src;

                // 正常运行模式：检查频率变化是否超过缓解阈值
                if (v > mitigation_threshold_aux) {
                    classification = MALICIOUS;
                }
            }

            if (classification != LEGITIMATE) {
                ipv4_dpi_lpm.apply();  // 使用备用转发表
            } else {
                ipv4_lpm.apply();      // 使用常规转发表
            }
        }
    }
} // Ingress end

#endif  /* _INGRESS_P4_ */
