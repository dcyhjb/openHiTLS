/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

#include "hitls_build.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_eal_md.h"
#include "eal_md_local.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_mac.h"

#include "test.h"
#include "helper.h"
#include "crypto_test_util.h"

#include "securec.h"
#include "crypt_util_rand.h"

#ifndef HITLS_BSL_SAL_MEM
void *TestMalloc(uint32_t len)
{
    return malloc((size_t)len);
}
#endif

void TestMemInit(void)
{
#ifdef HITLS_BSL_SAL_MEM
    return;
#else
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC_CB_FUNC, TestMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE_CB_FUNC, free);
#endif
}

#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_DRBG)
typedef struct {
    CRYPT_Data *entropy;
    CRYPT_Data *nonce;
    CRYPT_Data *pers;

    CRYPT_Data *addin1;
    CRYPT_Data *entropyPR1;

    CRYPT_Data *addin2;
    CRYPT_Data *entropyPR2;

    CRYPT_Data *retBits;
} DRBG_Vec_t;

#ifdef HITLS_CRYPTO_ENTROPY
static int32_t GetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    if (lenRange == NULL) {
        Print("getEntropy Error lenRange NULL\n");
        return CRYPT_NULL_INPUT;
    }
    if (ctx == NULL || entropy == NULL) {
        Print("getEntropy Error\n");
        lenRange->max = strength;
        return CRYPT_NULL_INPUT;
    }

    DRBG_Vec_t *seedCtx = (DRBG_Vec_t *)ctx;

    entropy->data = seedCtx->entropy->data;
    entropy->len = seedCtx->entropy->len;

    return CRYPT_SUCCESS;
}

static void CleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    (void)entropy;
    return;
}
#endif

int32_t TestSimpleRand(uint8_t *buff, uint32_t len)
{
    int rand = open("/dev/urandom", O_RDONLY);
    if (rand < 0) {
        printf("open /dev/urandom failed.\n");
        return -1;
    }
    int l = read(rand, buff, len);
    if (l < 0) {
        printf("read from /dev/urandom failed. errno: %d.\n", errno);
        close(rand);
        return -1;
    }
    close(rand);
    return 0;
}

int TestRandInit(void)
{
    int drbgAlgId = GetAvailableRandAlgId();
    if (drbgAlgId == -1) {
        Print("Drbg algs are disabled.");
        return CRYPT_NOT_SUPPORT;
    }

#ifdef HITLS_CRYPTO_ENTROPY
    CRYPT_RandSeedMethod seedMeth = {GetEntropy, CleanEntropy, NULL, NULL};
    uint8_t entropy[64] = {0};
    CRYPT_Data tempEntropy = {entropy, sizeof(entropy)};
    DRBG_Vec_t seedCtx = {0};
    seedCtx.entropy = &tempEntropy;
    return CRYPT_EAL_RandInit(drbgAlgId, &seedMeth, (void *)&seedCtx, NULL, 0);
#else
    return CRYPT_EAL_RandInit(drbgAlgId, NULL, NULL, NULL, 0);
#endif
}
#endif
