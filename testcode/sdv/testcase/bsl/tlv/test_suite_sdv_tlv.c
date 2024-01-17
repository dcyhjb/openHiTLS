/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */

#include "tlv.h"
#include "bsl_errno.h"

/* END_HEADER */

/**
 * @test  SDV_BSL_TLV_Find_API_TC001
 * @title  Find tlv value pos test
 * @precon  nan
 * @brief
 *    1. Invoke BSL_TLV_Pack to construct a tlv buffer. Expected result 1 is obtained.
 *    2. Invoke BSL_TLV_FindValuePos to find a type which valid. Expected result 2 is obtained.
 *    3. Invoke BSL_TLV_FindValuePos to find a type which invalid. Expected result 3 is obtained.
 * @expect
 *    1. Expected success
 *    2. Expected success
 *    3. Expected failure
 */
/* BEGIN_CASE */
void SDV_BSL_TLV_Find_API_TC001(void)
{
    int ret;
    uint32_t type = 0x0101;
    uint16_t version = 1;

    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sizeof(version);
    tlv.value = (uint8_t *)&version;

    uint32_t encLen = 0;
    uint8_t data[1024] = {0};
    ret = BSL_TLV_Pack(&tlv, data, sizeof(data), &encLen);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    uint32_t offset = 0;
    uint32_t length = 0;
    ret = BSL_TLV_FindValuePos(type, data, encLen, &offset, &length);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    uint32_t invalidType = 0x0102;
    ret = BSL_TLV_FindValuePos(invalidType, data, encLen, &offset, &length);
    ASSERT_TRUE(ret == BSL_TLV_ERR_NO_WANT_TYPE);
exit:
    return;
}
/* END_CASE */