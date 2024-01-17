/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bn_basic.h"
#include "bn_bincal.h"
#include "crypt_util_rand.h"

static int32_t RandGenerate(BN_BigNum *r, uint32_t bits)
{
    uint8_t *buf = NULL;
    int32_t ret;
    uint32_t room = BITS_TO_BN_UNIT(bits);
    if (BnExtend(r, room) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    buf = (uint8_t *)r->data;
    BN_Zeroize(r);
    ret = CRYPT_Rand(buf, room * sizeof(BN_UINT));
    if (ret == CRYPT_NO_REGIST_RAND) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_RAND_GEN_FAIL);
        return CRYPT_BN_RAND_GEN_FAIL;
    }
    BN_UINT mask = (BN_UINT)(-1) >> ((BN_UINT_BITS - bits % BN_UINT_BITS) % BN_UINT_BITS);
    r->data[room - 1] &= mask;
    r->size = BinFixSize(r->data, room);
    return ret;
}

static int32_t CheckTopAndBottom(uint32_t bits, uint32_t top, uint32_t bottom)
{
    if (top > BN_RAND_TOP_TWOBIT) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_RAND_TOP_BOTTOM);
        return CRYPT_BN_ERR_RAND_TOP_BOTTOM;
    }
    if (bottom > BN_RAND_BOTTOM_TWOBIT) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_RAND_TOP_BOTTOM);
        return CRYPT_BN_ERR_RAND_TOP_BOTTOM;
    }
    if (top > bits || bottom > bits) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_RAND_BITS_NOT_ENOUGH);
        return CRYPT_BN_ERR_RAND_BITS_NOT_ENOUGH;
    }
    return CRYPT_SUCCESS;
}

int32_t BN_Rand(BN_BigNum *r, uint32_t bits, uint32_t top, uint32_t bottom)
{
    if (r == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CheckTopAndBottom(bits, top, bottom);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (bits == 0) {
        return BN_Zeroize(r);
    }

    if (bits > BN_MAX_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_BITS_TOO_MAX);
        return CRYPT_BN_BITS_TOO_MAX;
    }
    ret = RandGenerate(r, bits);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    r->data[0] |= (bottom == BN_RAND_BOTTOM_TWOBIT) ? 0x3 : (BN_UINT)bottom;  // CheckTopAndBottom ensure that bottom>0
    if (top == BN_RAND_TOP_ONEBIT) {
        BN_SetBit(r, bits - 1);
    } else if (top == BN_RAND_TOP_TWOBIT) {
        BN_SetBit(r, bits - 1);
        BN_SetBit(r, bits - 2); /* the most significant 2 bits are 1 */
    }
    r->size = BinFixSize(r->data, r->room);
    return ret;
}

static int32_t InputCheck(const BN_BigNum *r, const BN_BigNum *p)
{
    if (r == NULL || p == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (BN_IsZero(p)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_RAND_ZERO);
        return CRYPT_BN_ERR_RAND_ZERO;
    }
    if (p->sign == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_RAND_NEGATIVE);
        return CRYPT_BN_ERR_RAND_NEGATIVE;
    }
    return CRYPT_SUCCESS;
}

int32_t BN_RandRange(BN_BigNum *r, const BN_BigNum *p)
{
    const int32_t maxCnt = 100; /* try 100 times */
    int32_t tryCnt = 0;
    int32_t ret;

    ret = InputCheck(r, p);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Zeroize(r);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (BN_IsOne(p)) {
        return CRYPT_SUCCESS;
    }

    uint32_t bits = BN_Bits(p);
    do {
        tryCnt++;
        if (tryCnt > maxCnt) {
            /* The success rate is more than 50%. */
            /* Return a failure if failed to generated after try 100 times */
            BSL_ERR_PUSH_ERROR(CRYPT_BN_RAND_GEN_FAIL);
            return CRYPT_BN_RAND_GEN_FAIL;
        }
        ret = RandGenerate(r, bits);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } while (BinCmp(r->data, r->size, p->data, p->size) >= 0);

    return ret;
}

#endif /* HITLS_CRYPTO_BN */
