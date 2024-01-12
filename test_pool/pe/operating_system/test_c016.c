/** @file
 * Copyright (c) 2023, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#include "val/include/sbsa_avs_val.h"
#include "val/include/sbsa_avs_pe.h"
#include "val/include/val_interface.h"
#include "val/include/sbsa_avs_mpam.h"

#define TEST_NUM   (AVS_PE_TEST_NUM_BASE  +  16)
#define TEST_RULE  "S_MPAM_PE"
#define TEST_DESC  "Check MPAM LLC Requirements       "

#define MEM_CACHE_LEVEL_1 1

static void payload(void)
{
    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
    uint32_t msc_node_cnt;
    uint32_t rsrc_node_cnt;
    uint32_t msc_index, rsrc_index;
    uint32_t pptt_llc_index;
    uint64_t pptt_cache_id;
    uint32_t test_run = 0;
    uint32_t ris_supported = 0;
    uint32_t cpor_supported = 0;
    uint32_t pe_prox_domain;
    uint32_t pptt_llc_cpor_supported = 0;
    uint32_t memside_llc_cpor_supported = 0;
    uint64_t msc_rsrc_desc1;
    uint64_t msc_rsrc_desc2;

    if (g_sbsa_level < 5) {
        val_set_status(index, RESULT_SKIP(g_sbsa_level, TEST_NUM, 01));
        return;
    }

    /* Check if PE implements FEAT_MPAM */
    if (!((VAL_EXTRACT_BITS(val_pe_reg_read(ID_AA64PFR0_EL1), 40, 43) > 0) ||
        (VAL_EXTRACT_BITS(val_pe_reg_read(ID_AA64PFR1_EL1), 16, 19) > 0))) {
            val_set_status(index, RESULT_SKIP(g_sbsa_level, TEST_NUM, 02));
            return;
    }

    /* Find the LLC cache identifier */
    pptt_llc_index = val_cache_get_llc_index();
    if (pptt_llc_index == CACHE_TABLE_EMPTY) {
        val_print(AVS_PRINT_ERR, "\n       PPTT table empty", 0);
        val_set_status(index, RESULT_SKIP(g_sbsa_level, TEST_NUM, 03));
        return;
    }
    pptt_cache_id = val_cache_get_info(CACHE_ID, pptt_llc_index);

    if (pptt_cache_id == INVALID_CACHE_INFO) {
        val_print(AVS_PRINT_ERR, "\n       LLC invalid in PPTT", 0);
        val_set_status(index, RESULT_SKIP(g_sbsa_level, TEST_NUM, 04));
        return;
    }

    /* Check in the MPAM table which MSC is attached to the LLC */
    msc_node_cnt = val_mpam_get_msc_count();
    val_print(AVS_PRINT_DEBUG, "\n       MSC count = %d", msc_node_cnt);

    if (msc_node_cnt == 0) {
        val_print(AVS_PRINT_ERR, "\n       MSC count is 0", 0);
        val_set_status(index, RESULT_FAIL(g_sbsa_level, TEST_NUM, 01));
        return;
    }

    /* visit each MSC node and check for cache resources */
    for (msc_index = 0; msc_index < msc_node_cnt; msc_index++) {
        rsrc_node_cnt = val_mpam_get_info(MPAM_MSC_RSRC_COUNT, msc_index, 0);

        val_print(AVS_PRINT_DEBUG, "\n       msc index  = %d", msc_index);
        val_print(AVS_PRINT_DEBUG, "\n       Resource count = %d", rsrc_node_cnt);

        cpor_supported = 0;

        ris_supported = val_mpam_msc_supports_ris(msc_index);
        val_print(AVS_PRINT_INFO, "\n       RIS Support = %d", ris_supported);

        for (rsrc_index = 0; rsrc_index < rsrc_node_cnt; rsrc_index++) {

            /* check whether the resource location is PE cache */
            if (val_mpam_get_info(MPAM_MSC_RSRC_TYPE, msc_index, rsrc_index) ==
                MPAM_RSRC_TYPE_PE_CACHE) {
                val_print(AVS_PRINT_DEBUG, "\n       rsrc index  = %d", rsrc_index);
                msc_rsrc_desc1 = val_mpam_get_info(MPAM_MSC_RSRC_DESC1, msc_index, rsrc_index);

                /* match pptt llc cache id */
                val_print(AVS_PRINT_DEBUG, "\n       rsrc descriptor 1  = %llx", msc_rsrc_desc1);
                if (msc_rsrc_desc1 == pptt_cache_id) {
                    test_run = 1;
                    /* Select resource instance if RIS feature implemented */
                    if (ris_supported)
                        val_mpam_memory_configure_ris_sel(msc_index, rsrc_index);

                    /* Check CPOR are present */
                    if (val_mpam_supports_cpor(msc_index)) {
                        val_print(AVS_PRINT_DEBUG,
                                  "\n       CPOR Supported by LLC for rsrc_index %d", rsrc_index);
                        cpor_supported = 1;
                        break;
                    }
                    val_print(AVS_PRINT_DEBUG,
                              "\n       CPOR Not Supported by LLC for rsrc_index %d", rsrc_index);
                }
            }
        }
        if (cpor_supported)
            break;
    }

    if (!test_run) {
        val_print(AVS_PRINT_ERR, "\n       No MSC found on PPTT LLC", 0);
    } else if (!cpor_supported) {
        val_print(AVS_PRINT_ERR, "\n       CPOR unsupported by PPTT LLC", 0);
    } else {
        pptt_llc_cpor_supported = 1;
    }

    /* test mem-side cache for cpor */
    val_print(AVS_PRINT_DEBUG, "\n\n       Testing mem-side caches for CPOR support", 0);
    cpor_supported = 0;
    test_run = 0;
    pe_prox_domain = val_srat_get_info(SRAT_GICC_PROX_DOMAIN, val_pe_get_uid(index));
    /* visit each MSC node and check for mem cache resources */
    for (msc_index = 0; msc_index < msc_node_cnt; msc_index++) {
        rsrc_node_cnt = val_mpam_get_info(MPAM_MSC_RSRC_COUNT, msc_index, 0);

        val_print(AVS_PRINT_DEBUG, "\n       MSC index  = %d", msc_index);
        val_print(AVS_PRINT_DEBUG, "\n       Resource count = %d", rsrc_node_cnt);

        ris_supported = val_mpam_msc_supports_ris(msc_index);
        val_print(AVS_PRINT_INFO, "\n       RIS support = %d", ris_supported);

        for (rsrc_index = 0; rsrc_index < rsrc_node_cnt; rsrc_index++) {
            /* check whether the resource type is a mem-cache */
            if (val_mpam_get_info(MPAM_MSC_RSRC_TYPE, msc_index, rsrc_index) ==
                MPAM_RSRC_TYPE_MEM_SIDE_CACHE) {
                val_print(AVS_PRINT_DEBUG, "\n       rsrc index  = %d", rsrc_index);
                msc_rsrc_desc1 = val_mpam_get_info(MPAM_MSC_RSRC_DESC1, msc_index, rsrc_index);
                msc_rsrc_desc2 = val_mpam_get_info(MPAM_MSC_RSRC_DESC2, msc_index, rsrc_index);
                val_print(AVS_PRINT_DEBUG, "\n       rsrc descriptor 1  = %llx", msc_rsrc_desc1);
                val_print(AVS_PRINT_DEBUG, "\n       rsrc descriptor 2  = %llx", msc_rsrc_desc2);

                /* check if mem-side cache matches with PE proximity domain
                   and cache level == 1 for mem-side LLC (based on assumption that mem-cache nearer to memory is LLC) */
                if ((msc_rsrc_desc2 == pe_prox_domain) && (msc_rsrc_desc1 == MEM_CACHE_LEVEL_1)) {
                    test_run = 1;
                    /* Select resource instance if RIS feature implemented */
                    if (ris_supported)
                        val_mpam_memory_configure_ris_sel(msc_index, rsrc_index);

                    /* Check CPOR are present */
                    if (val_mpam_supports_cpor(msc_index)) {
                        val_print(AVS_PRINT_DEBUG,
                                  "\n       CPOR Supported by mem-side cache with rsrc_index %d", rsrc_index);
                        cpor_supported |= 1;
                    }
                    val_print(AVS_PRINT_DEBUG,
                              "\n       CPOR Not Supported by mem-side cache with rsrc_index %d", rsrc_index);
                }
            }
        }
    }

    if (!test_run) {
        val_print(AVS_PRINT_ERR, "\n       No MSC found on mem-side LLC", 0);
    } else if (!cpor_supported) {
        val_print(AVS_PRINT_ERR, "\n       CPOR unsupported by mem-side LLC", 0);
    } else {
        memside_llc_cpor_supported = 1;
    }

    /* if either of PPTT LLC or mem-side LLC supports cache portioning (CPOR) pass the test */
    if (pptt_llc_cpor_supported || memside_llc_cpor_supported) {
        val_set_status(index, RESULT_PASS(g_sbsa_level, TEST_NUM, 01));
    }
    else {
        val_set_status(index, RESULT_FAIL(g_sbsa_level, TEST_NUM, 02));
    }

    return;
}

uint32_t c016_entry(uint32_t num_pe)
{
    uint32_t status = AVS_STATUS_FAIL;

    num_pe = 1;
    status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, g_sbsa_level, TEST_RULE);
    /* This check is when user is forcing us to skip this test */
    if (status != AVS_STATUS_SKIP)
        val_run_test_payload(TEST_NUM, num_pe, payload, 0);

    /* get the result from PE and check for failure */
    status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);
    val_report_status(0, SBSA_AVS_END(g_sbsa_level, TEST_NUM), TEST_RULE);

    return status;
}
