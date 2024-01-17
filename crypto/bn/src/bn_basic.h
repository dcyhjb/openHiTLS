/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef BN_BASIC_H
#define BN_BASIC_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include <stdbool.h>
#include "crypt_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BN_UINT_BITS ((uint32_t)sizeof(BN_UINT) << 3)
#define BITS_TO_BN_UNIT(bits) (((bits) + BN_UINT_BITS - 1) / BN_UINT_BITS)

struct BigNum {
    bool sign; /* *< BigNum sign: negtive(true) or not(false) */
    uint32_t size; /* *< BigNum size (count of BN_UINT) */
    uint32_t room; /* *< BigNum max size (count of BN_UINT) */
    uint32_t flag; /* *< BigNum flag */
    BN_UINT *data; /* *< BigNum data chunk(most significant limb at the largest) */
};

struct BnMont {
    uint32_t mSize;   /* *< size of mod in BN_UINT */
    BN_UINT k0;         /* *< low word of (1/(r - mod[0])) mod r */
    BN_UINT *mod;       /* *< mod */
    BN_UINT *montRR;    /* *< mont_enc(1) */
    BN_UINT *b;         /* *< tmpb(1) */
    BN_UINT *t;         /* *< tmpt(1) ^ 2 */
};

struct BnCbCtx {
    void *arg; // callback parameter
    BN_CallBack cb; // callback function, which is defined by the user
};

/* Find a pointer address aligned by 'alignment' bytes in the [ptr, ptr + alignment - 1] range.
   The input parameter alignment cannot be 0. */
static inline BN_UINT *AlignedPointer(const void *ptr, uintptr_t alignment)
{
    uint8_t *p = (uint8_t *)(uintptr_t)ptr + alignment - 1;
    return (BN_UINT *)((uintptr_t)p - (uintptr_t)p % alignment);
}

uint32_t BnExtend(BN_BigNum *a, uint32_t words);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_BN

#endif // BN_BASIC_H
