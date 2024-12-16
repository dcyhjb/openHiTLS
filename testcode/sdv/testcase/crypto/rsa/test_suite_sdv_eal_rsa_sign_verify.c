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
/* INCLUDE_BASE test_suite_sdv_eal_rsa */

/* BEGIN_HEADER */

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "bsl_errno.h"
#include "crypt_eal_md.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
/* END_HEADER */

#define CRYPT_EAL_PKEY_KEYMGMT_OPERATE 0

int MD_Data(CRYPT_MD_AlgId mdId, Hex *msgIn, Hex *mdOut)
{
    uint32_t outLen;
    CRYPT_EAL_MdCTX *mdCtx = NULL;
    uint32_t mdOutLen = CRYPT_EAL_MdGetDigestSize(mdId);
    ASSERT_TRUE(mdOutLen != 0);
    mdOut->x = (uint8_t *)malloc(mdOutLen);
    ASSERT_TRUE(mdOut->x != NULL);
    mdOut->len = mdOutLen;
    outLen = mdOutLen;
    mdCtx = CRYPT_EAL_MdNewCtx(mdId);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_MdNewCtx", mdCtx != NULL);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_MdInit", CRYPT_EAL_MdInit(mdCtx) == 0);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_MdUpdate", CRYPT_EAL_MdUpdate(mdCtx, msgIn->x, msgIn->len) == 0);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_MdFinal", CRYPT_EAL_MdFinal(mdCtx, mdOut->x, &outLen) == 0);
    mdOut->len = outLen;
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return SUCCESS;

exit:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    free(mdOut->x);
    mdOut->x = NULL;
    return FAIL;
}

/**
 * @test   SDV_CRYPTO_RSA_SIGN_API_TC001
 * @title  RSA CRYPT_EAL_PkeySign: Wrong parameters.
 * @precon Create the context of the rsa algorithm, set private key and set padding type to pkcsv15:
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1) pkey = null, expected result 1.
 *       (2) data = null, dataLen = 0, expected result 2.
 *       (3) data = null, dataLen != 0, expected result 3.
 *       (4) data != null, dataLen = 0, expected result 4.
 *       (5) sign = null, signLen != 0, expected result 5.
 *       (6) sign != null, signLen = 0, expected result 6.
 *       (7) sign != null, signLen == NULL, expected result 7.
 *    2. Call the CRYPT_EAL_PkeySetPrv method with incorrect hash id, expected result 8:
 *       CRYPT_MD_MD5, CRYPT_MD_SHA1, CRYPT_MD_SM3, CRYPT_MD_MAX
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_NULL_INPUT
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_NULL_INPUT
 *    6. CRYPT_RSA_BUFF_LEN_NOT_ENOUGH
 *    7. CRYPT_NULL_INPUT
 *    8. Return CRYPT_RSA_ERR_ALGID or CRYPT_EAL_ERR_ALGID
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_API_TC001(Hex *n, Hex *d, int isProvider)
{
    int32_t ret;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPrv privaKey = {0};
    uint8_t *data = NULL;
    uint8_t *sign = NULL;
    uint32_t signLen = d->len + 1;
    uint32_t dataLen = signLen;
    int32_t pkcsv15 = CRYPT_MD_SHA224;
    CRYPT_MD_AlgId errIdList[] = {CRYPT_MD_MD5, CRYPT_MD_SHA1, CRYPT_MD_SM3, CRYPT_MD_MAX};

    /* Malloc signature buffer */
    sign = (uint8_t *)malloc(signLen);
    data = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(sign != NULL && data != NULL);
    SetRsaPrvKey(&privaKey, n->x, n->len, d->x, d->len);

    TestMemInit();
    if (isProvider == 1) {
        pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkeyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkeyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &privaKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(NULL, CRYPT_MD_SHA224, data, dataLen, sign, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, NULL, 0, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, NULL, dataLen, sign, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, data, 0, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, data, dataLen, NULL, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, data, dataLen, sign, NULL), CRYPT_NULL_INPUT);
    signLen = 0;
    ASSERT_EQ(
        CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, data, dataLen, sign, &signLen), CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);

    signLen = dataLen;
    for (int i = 0; i < (int)(sizeof(errIdList) / sizeof(CRYPT_MD_AlgId)); i++) {
        ret = CRYPT_EAL_PkeySign(pkeyCtx, errIdList[i], data, dataLen, sign, &signLen);
        ASSERT_TRUE(ret == CRYPT_RSA_ERR_ALGID || ret == CRYPT_EAL_ERR_ALGID);
    }
exit:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(data);
    free(sign);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_PKCSV15_FUNC_TC001
 * @title  RSA EAL layer signature function test: PKCSV15, sha224
 * @precon nan
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set the private key for pkeyCtx, expected result 2
 *    3. Set the padding algorithm to PKCS15 and set the hash value to SHA224, expected result 3
 *    4. Call the CRYPT_EAL_PkeySign method with invalid mdId, expected result 4
 *    5. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. CRYPT_EAL_ERR_ALGID
 *    5. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_PKCSV15_FUNC_TC001(Hex *n, Hex *d, Hex *msg, Hex *sign, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPrv privaKey = {0};
    uint8_t *signdata = NULL;
    uint32_t signLen = sign->len;
    int32_t pkcsv15 = CRYPT_MD_SHA224;

    /* Malloc signature buffer */
    signdata = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(signdata != NULL);
    SetRsaPrvKey(&privaKey, n->x, n->len, d->x, d->len);
    TestMemInit();

    if (isProvider == 1) {
        pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkeyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkeyCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &privaKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(signdata);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_PKCSV15_FUNC_TC002
 * @title  RSA EAL layer signature function test: PKCSV15
 * @precon nan
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set the private key for pkeyCtx, expected result 2
 *    3. Set the padding algorithm to PKCS15 and set the hash value to SHA2, expected result 3
 *    4. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 4
 *    5. Compare the signature result and the signature vector., expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_SUCCESS
 *    5. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_PKCSV15_FUNC_TC002(int mdId, Hex *n, Hex *d, Hex *msg, Hex *sign, int isProvider)
{
    if (IsMdAlgDisabled(mdId)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPrv privaKey = {0};
    int32_t pkcsv15 = mdId;
    uint8_t *signdata = NULL;
    uint32_t signLen;

    SetRsaPrvKey(&privaKey, n->x, n->len, d->x, d->len);

    TestMemInit();

    if (isProvider == 1) {
        pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkeyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkeyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &privaKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), 0);

    /* Malloc signature buffer */
    signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    ASSERT_EQ(signLen, sign->len);
    signdata = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(signdata != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("CRYPT_EAL_PkeySign Compare", sign->x, sign->len, signdata, signLen);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(signdata);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC001
 * @title  RSA EAL layer signature function test: Pss
 * @precon nan
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set the private key for pkeyCtx, expected result 2
 *    3. Set the padding algorithm to PKCS15 and set the hash value to SHA2, expected result 3
 *    4. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 4
 *    5. Compare the signature result and the signature vector., expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS
 *    5. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC001(int mdId, Hex *n, Hex *d, Hex *msg, Hex *sign, Hex *salt, int isProvider)
{
    if (IsMdAlgDisabled(mdId)) {
        SKIP_TEST();
    }
    int i;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPrv privaKey = {0};
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &salt->len, sizeof(salt->len), 0},
        BSL_PARAM_END};
    uint8_t *signdata = NULL;
    uint32_t signLen = sign->len;

    SetRsaPrvKey(&privaKey, n->x, n->len, d->x, d->len);

    /* Malloc signature buffer */
    signdata = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(signdata != NULL);

    TestMemInit();

    if (isProvider == 1) {
        pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkeyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkeyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &privaKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);

    /* Repeat signature 2 times. */
    for (i = 0; i < 2; i++) {
        if (salt->len != 0) {
            ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_SALT, salt->x, salt->len), CRYPT_SUCCESS);
        }
        ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);
        ASSERT_COMPARE("Compare Sign Data", signdata, signLen, sign->x, sign->len);
        signLen = sign->len;
    }

exit:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(signdata);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC002
 * @title  RSA EAL layer signature function test: Pss with different salt lengths.
 * @precon nan
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Initialize the DRBG, expected result 2
 *    3. Set the private key for pkeyCtx, expected result 3
 *    4. Set the padding algorithm to PSS and set the hash value to SHA2, expected result 4
 *    5. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-5. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC002(int mdId, Hex *n, Hex *d, Hex *msg, int saltLen, int isProvider)
{
    if (IsMdAlgDisabled(mdId)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPrv privaKey = {0};
    uint8_t *signdata = NULL;
    uint32_t signLen;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    SetRsaPrvKey(&privaKey, n->x, n->len, d->x, d->len);

    TestMemInit();

    if (isProvider == 1) {
        pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkeyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkeyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &privaKey), CRYPT_SUCCESS);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);

    /* Malloc signature buffer */
    signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    ASSERT_TRUE(signLen != 0);
    signdata = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(signdata != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);
exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(signdata);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC003
 * @title  RSA EAL layer signature function test: Do not set the salt length of PSS.
 * @precon Vectors: private key, msg.
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set the private key for pkeyCtx, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Set the padding algorithm to PSS, saltLen is 0 | -1 | -2, expected result 4
 *    5. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC003(Hex *n, Hex *d, Hex *msg, int saltLen, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPrv privaKey = {0};
    uint8_t *signdata = NULL;
    uint32_t signLen;
    int32_t mdId = CRYPT_MD_SHA224;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    SetRsaPrvKey(&privaKey, n->x, n->len, d->x, d->len);

    TestMemInit();

    if (isProvider == 1) {
        pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkeyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkeyCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &privaKey), CRYPT_SUCCESS);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);

    /* Malloc signature buffer */
    signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    ASSERT_TRUE(signLen != 0);
    signdata = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(signdata != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(signdata);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC001
 * @title  RSA EAL sign/verify and signData/verifyData:PKCSV15, sha256
 * @precon
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeySetPara, where bits are: 1024/2048/4096, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGen to generate a key pair again, expected result 5
 *    6. Set padding type to pkcsv15, expected result 6
 *    7. Call the CRYPT_EAL_PkeySign method and use pkey to sign a piece of data, expected result 7
 *    8. Call the CRYPT_EAL_PkeyVerify method and use pkey to verify the signed data, expected result 8
 *    9. Call the CRYPT_EAL_PkeySignData method and use pkey to sign a piece of hash data, expected result 9
 *    10. Call the CRYPT_EAL_PkeyVerifyData method and use pkey to verify the signed data, expected result 10
 *    11. Allocate the memory for the CRYPT_EAL_PkeyCtx, named cpyCtx, expected result 11
 *    12. Call the CRYPT_EAL_PkeyCopyCtx to copy pkeyCtx, expected result 12
 *    13. Call the CRYPT_EAL_PkeySignData method and use cpyCtx to sign a piece of data, expected result 13
 *    14. Call the CRYPT_EAL_PkeyVerifyData method and use cpyCtx to verify the signed data, expected result 14
 * @expect
 *    1. Success, and context is not NULL.
 *    2-10. CRYPT_SUCCESS
 *    11. Success.
 *    12-14. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC001(int bits, int isProvider)
{
#ifndef HITLS_CRYPTO_SHA256
    SKIP_TEST();
#endif
    uint32_t signLen = (bits + 7) >> 3;  // keybytes == (keyBits + 7) >> 3 */
    int mdId = CRYPT_MD_SHA256;
    uint8_t data[500] = {0};
    const uint32_t dataLen = sizeof(data);
    uint8_t hash[32];  // SHA256 digest length: 32
    const uint32_t hashLen = sizeof(hash);
    uint8_t e[] = {1, 0, 1};

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *cpyCtx = NULL;
    int32_t pkcsv15 = mdId;
    CRYPT_EAL_PkeyPara para = {0};

    SetRsaPara(&para, e, 3, bits);

    uint8_t *sign = malloc(signLen);
    ASSERT_TRUE_AND_LOG("Malloc Sign Buffer", sign != NULL);

    TestMemInit();

    if (isProvider == 1) {
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, mdId, data, dataLen, sign, &signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, data, dataLen, sign, signLen), CRYPT_SUCCESS);

    signLen = (bits + 7) >> 3;  // keybytes == (keyBits + 7) >> 3 */
    memset_s(hash, sizeof(hash), 'A', sizeof(hash));
    ASSERT_EQ(CRYPT_EAL_PkeySignData(pkey, hash, hashLen, sign, &signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(pkey, hash, hashLen, sign, signLen), CRYPT_SUCCESS);

    if (isProvider == 1) {
        cpyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ED25519,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        cpyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED25519);
    }
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx, pkey), CRYPT_SUCCESS);

    signLen = (bits + 7) >> 3;
    ASSERT_EQ(CRYPT_EAL_PkeySign(cpyCtx, mdId, data, dataLen, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(cpyCtx, mdId, data, dataLen, sign, signLen), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx);
    free(sign);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PSS_FUNC_TC001
 * @title  RSA EAL signData/verifyData: pss, sha256, saltLen=32bytes
 * @precon
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeySetPara, where bits is 1025, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 4
 *    5. Set padding type to pkcsv15 and set salt(32 bytes), expected result 5
 *    6. Call the CRYPT_EAL_PkeySignData method and use pkey to sign a piece of data, expected result 6
 *    7. Call the CRYPT_EAL_PkeyVerifyData method and use pkey to verify the signed data, expected result 7
 *    8. Allocate the memory for the CRYPT_EAL_PkeyCtx, named cpyCtx, expected result 8
 *    9. Call the CRYPT_EAL_PkeyCopyCtx to copy pkeyCtx, expected result 9
 *    10. Call the CRYPT_EAL_PkeySignData method and use cpyCtx to sign a piece of data, expected result 10
 *    11. Call the CRYPT_EAL_PkeyVerifyData method and use cpyCtx to verify the signed data, expected result 11
 * @expect
 *    1. Success, and context is not NULL.
 *    2-7. CRYPT_SUCCESS
 *    8. Success.
 *    9-11. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PSS_FUNC_TC001(int bits, int isProvider)
{
#ifndef HITLS_CRYPTO_SHA256
    SKIP_TEST();
#endif
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *cpyCtx = NULL;
    int32_t mdId = CRYPT_MD_SHA256;
    int32_t saltLen = 32;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    CRYPT_EAL_PkeyPara para = {0};
    uint8_t e[] = {1, 0, 1};
    uint8_t salt[100];
    uint32_t signLen = (bits + 7) >> 3;  // keybytes == (keyBits + 7) >> 3 */
    uint8_t hash[32];                    // SHA256 digest length 32
    const uint32_t hashLen = sizeof(hash);

    memset_s(hash, sizeof(hash), 'A', sizeof(hash));
    (void)memset_s(salt, sizeof(salt), 'A', sizeof(salt));
    uint8_t *sign = malloc(signLen);
    ASSERT_TRUE(sign != NULL);
    SetRsaPara(&para, e, 3, bits);

    TestMemInit();

    if (isProvider == 1) {
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_TRUE_AND_LOG("Malloc Sign Buffer", sign != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_SALT, (uint8_t *)salt, 32), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySignData(pkey, hash, hashLen, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(pkey, hash, hashLen, sign, signLen), CRYPT_SUCCESS);

    if (isProvider == 1) {
        cpyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ED25519,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        cpyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED25519);
    }
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx, pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySignData(cpyCtx, hash, hashLen, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(cpyCtx, hash, hashLen, sign, signLen), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx);
    free(sign);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC002
 * @title  RSA EAL sign/verify:Generate a key pair, set pubKey, PKCSV15, sha256
 * @precon
 * @brief
 *    1. Create the contexts(pkey, pkey2) of the rsa algorithm, expected result 1
 *    2. Set para for pkey and pkey2, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 4
 *    5. Get public key from pkey, expected result 5
 *    6. Set public key for pkey2, expected result 6
 *    7. Set padding type to pkcsv15 for pkey and pkey2, expected result 7
 *    8. Call the CRYPT_EAL_PkeySign method and use pkey to sign a piece of data, expected result8
 *    9. Call the CRYPT_EAL_PkeyVerify method and use pkey2 to verify the signed data, expected result 9
 * @expect
 *    1. Success, and context is not NULL.
 *    2-9. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC002(int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    int32_t pkcsv15 = CRYPT_MD_SHA256;
    uint8_t pubN[600];
    uint8_t pubE[600];
    uint8_t e[] = {1, 0, 1};
    uint8_t sign[200];
    uint32_t signLen = 200;  // 200bytes is greater than 1024 bits.
    uint8_t data[500] = {0};
    const uint32_t dataLen = 500;

    SetRsaPara(&para, e, 3, 1024);
    SetRsaPubKey(&pubKey, pubN, 600, pubE, 600);

    TestMemInit();

    if (isProvider == 1) {
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    if (isProvider == 1) {
        pkey2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkey2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkey != NULL && pkey2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey2, &para), CRYPT_SUCCESS);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey2, &pubKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey2, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, data, dataLen, sign, &signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey2, CRYPT_MD_SHA256, data, dataLen, sign, signLen), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC003
 * @title  RSA EAL sign/verify:Generate a key pair, set prvKey, PKCSV15, sha256
 * @precon
 * @brief
 *    1. Create the contexts(pkey, pkey2) of the rsa algorithm, expected result 1
 *    2. Set para for pkey and pkey2, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 4
 *    5. Get private key from pkey, expected result 5
 *    6. Set private key for pkey2, expected result 6
 *    7. Set padding type to pkcsv15 for pkey and pkey2, expected result 7
 *    8. Call the CRYPT_EAL_PkeySign method and use pkey2 to sign a piece of data, expected result8
 *    9. Call the CRYPT_EAL_PkeyVerify method and use pkey to verify the signed data, expected result 9
 * @expect
 *    1. Success, and context is not NULL.
 *    2-9. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC003(int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};
    int32_t pkcsv15 = CRYPT_MD_SHA256;
    uint8_t prvD[600];
    uint8_t prvN[600];
    uint8_t prvP[600];
    uint8_t prvQ[600];
    uint8_t e[] = {1, 0, 1};
    uint8_t sign[600];
    uint32_t signLen = 600;  // 600bytes > 1024bits
    uint8_t data[500] = {0};
    uint32_t dataLen = sizeof(data);

    SetRsaPara(&para, e, 3, 1024);
    prvKey.id = CRYPT_PKEY_RSA;
    prvKey.key.rsaPrv.d = prvD;
    prvKey.key.rsaPrv.dLen = 600;  // 600bytes > 1024bits
    prvKey.key.rsaPrv.n = prvN;
    prvKey.key.rsaPrv.nLen = 600;  // 600bytes > 1024bits
    prvKey.key.rsaPrv.p = prvP;
    prvKey.key.rsaPrv.pLen = 600;  // 600bytes > 1024bits
    prvKey.key.rsaPrv.q = prvQ;
    prvKey.key.rsaPrv.qLen = 600;  // 600bytes > 1024bits
    prvKey.key.rsaPrv.dP = NULL;
    prvKey.key.rsaPrv.dPLen = 0;
    prvKey.key.rsaPrv.dQ = NULL;
    prvKey.key.rsaPrv.dQLen = 0;
    prvKey.key.rsaPrv.qInv = NULL;
    prvKey.key.rsaPrv.qInvLen = 0;

    TestMemInit();

    if (isProvider == 1) {
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    if (isProvider == 1) {
        pkey2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkey2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkey != NULL && pkey2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey2, &para), CRYPT_SUCCESS);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey2, &prvKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey2, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey2, CRYPT_MD_SHA256, data, dataLen, sign, &signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, data, dataLen, sign, signLen), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_VERIFY_PKCSV15_FUNC_TC001
 * @title  Rsa verify-PKCS15
 * @precon
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set public key for pkeyCtx, expected result 2
 *    3. Set padding type to pkcsv15 for pkeyCtx, expected result 3
 *    4. Call the CRYPT_EAL_PkeyVerify method and use pkeyCtx to verify the signed data, expected result 4
 *    5. Calculate the hash value of msg, expected result 5
 *    6. Call the CRYPT_EAL_PkeyVerifyData method and use pkeyCtx to verify the signed data, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. Reutrn CRYPT_SUCCESS when expect is 0, otherwise return CRYPT_RSA_NOR_VERIFY_FAIL.
 *    5. SUCCESS
 *    6. Reutrn CRYPT_SUCCESS when expect is 0, otherwise return CRYPT_RSA_NOR_VERIFY_FAIL.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_VERIFY_PKCSV15_FUNC_TC001(
    int mdAlgId, Hex *n, Hex *e, Hex *msg, Hex *sign, int expect, int isProvider)
{
    if (IsMdAlgDisabled(mdAlgId)) {
        SKIP_TEST();
    }
    int ret;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPub publicKey = {0};
    int32_t pkcsv15 = mdAlgId;
    Hex mdOut = {0};

    TestMemInit();

    if (isProvider == 1) {
        pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkeyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkeyCtx != NULL);

    /* Set the public key.*/
    SetRsaPubKey(&publicKey, n->x, n->len, e->x, e->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkeyCtx, &publicKey), CRYPT_SUCCESS);

    /* Set padding. */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(pkeyCtx, mdAlgId, msg->x, msg->len, sign->x, sign->len);
    if (expect == SUCCESS) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(ret, CRYPT_RSA_NOR_VERIFY_FAIL);
    }

    ASSERT_TRUE(MD_Data(mdAlgId, msg, &mdOut) == SUCCESS);
    ret = CRYPT_EAL_PkeyVerifyData(pkeyCtx, mdOut.x, mdOut.len, sign->x, sign->len);
    if (expect == SUCCESS) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(ret, CRYPT_RSA_NOR_VERIFY_FAIL);
    }

    ret = CRYPT_EAL_PkeyVerifyData(NULL, mdOut.x, mdOut.len, sign->x, sign->len);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeyVerifyData", ret != CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(mdOut.x);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_VERIFY_PSS_FUNC_TC001
 * @title  Rsa verify-PSS
 * @precon
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set public key for pkeyCtx, expected result 2
 *    3. Set padding type to PSS for pkeyCtx, expected result 3
 *    4. Call the CRYPT_EAL_PkeyVerify method and use pkeyCtx to verify the signed data, expected result 4
 *    5. Calculate the hash value of msg, expected result 5
 *    6. Call the CRYPT_EAL_PkeyVerifyData method and use pkeyCtx to verify the signed data, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. Reutrn CRYPT_SUCCESS when expect is 0, otherwise return CRYPT_RSA_NOR_VERIFY_FAIL.
 *    5. SUCCESS
 *    6. Reutrn CRYPT_SUCCESS when expect is 0, otherwise return CRYPT_RSA_NOR_VERIFY_FAIL.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_VERIFY_PSS_FUNC_TC001(
    int mdAlgId, Hex *n, Hex *e, Hex *salt, Hex *msg, Hex *sign, int expect, int isProvider)
{
    if (IsMdAlgDisabled(mdAlgId)) {
        SKIP_TEST();
    }
    int ret;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPub publicKey = {0};
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdAlgId, sizeof(mdAlgId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdAlgId, sizeof(mdAlgId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &salt->len, sizeof(salt->len), 0},
        BSL_PARAM_END};
    Hex mdOut = {0};

    TestMemInit();

    if (isProvider == 1) {
        pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkeyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkeyCtx != NULL);

    /* Set the public key.*/
    SetRsaPubKey(&publicKey, n->x, n->len, e->x, e->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkeyCtx, &publicKey), CRYPT_SUCCESS);

    /* Set padding. */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(pkeyCtx, mdAlgId, msg->x, msg->len, sign->x, sign->len);
    if (expect == SUCCESS) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(ret, CRYPT_RSA_NOR_VERIFY_FAIL);
    }

    ASSERT_TRUE(MD_Data(mdAlgId, msg, &mdOut) == SUCCESS);
    ret = CRYPT_EAL_PkeyVerifyData(pkeyCtx, mdOut.x, mdOut.len, sign->x, sign->len);
    if (expect == SUCCESS) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(ret, CRYPT_RSA_NOR_VERIFY_FAIL);
    }

exit:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    if (mdOut.x != NULL) {
        free(mdOut.x);
    }
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_VERIFY_PSS_FUNC_TC002
 * @title  RSA verify PSS: saltLen is CRYPT_RSA_SALTLEN_TYPE_AUTOLEN
 * @precon
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set public key for pkeyCtx, expected result 2
 *    3. Set padding type to PSS(saltLen is CRYPT_RSA_SALTLEN_TYPE_AUTOLEN) for pkeyCtx, expected result 3
 *    4. Call the CRYPT_EAL_PkeyVerify method and use pkeyCtx to verify the signed data, expected result 4
 *    5. Calculate the hash value of msg, expected result 5
 *    6. Call the CRYPT_EAL_PkeyVerifyData method and use pkeyCtx to verify the signed data, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2-6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_VERIFY_PSS_FUNC_TC002(int mdAlgId, Hex *n, Hex *e, Hex *msg, Hex *sign, int isProvider)
{
    if (IsMdAlgDisabled(mdAlgId)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPub publicKey = {0};
    uint32_t signLen = CRYPT_RSA_SALTLEN_TYPE_AUTOLEN;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdAlgId, sizeof(mdAlgId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdAlgId, sizeof(mdAlgId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &signLen, sizeof(signLen), 0},
        BSL_PARAM_END};
    TestMemInit();

    if (isProvider == 1) {
        pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkeyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkeyCtx != NULL);

    /* Set the public key.*/
    SetRsaPubKey(&publicKey, n->x, n->len, e->x, e->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkeyCtx, &publicKey), CRYPT_SUCCESS);

    /* Set padding. */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyCtx, mdAlgId, msg->x, msg->len, sign->x, sign->len), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_BLINDING_FUNC_TC001
 * @title  RSA EAL sign and verify with blinding.
 * @precon nan
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set para, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 4
 *    5. Set CRYPT_RSA_BLINDING flag, expected result 5
 *    6. Set padding type, expected result 6
 *    7. Sign with HiTLS, expected result 7
 *    8. Verify with HiTLS, expected result 8
 * @expect
 *    1. Success, and context is not NULL.
 *    2-8. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_BLINDING_FUNC_TC001(int keyLen, int hashId, int padMode, Hex *msg, int saltLen, int isProvider)
{
    if (IsMdAlgDisabled(hashId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint8_t sign[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t dataLen = MAX_CIPHERTEXT_LEN;
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *newCtx = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    int paraSize;
    void *paraPtr;

    SetRsaPara(&para, e, 3, keyLen);
    int32_t pkcsv15 = hashId;
    if (padMode == CRYPT_CTRL_SET_RSA_EMSA_PSS) {
        paraSize = 0;
        paraPtr = pssParam;
    } else if (padMode == CRYPT_CTRL_SET_RSA_EMSA_PKCSV15) {
        paraSize = sizeof(pkcsv15);
        paraPtr = &pkcsv15;
    }

    if (isProvider == 1) {
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, padMode, paraPtr, paraSize) == CRYPT_SUCCESS);
    uint32_t flag = CRYPT_RSA_BLINDING;
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_FLAG, (void *)&flag, sizeof(uint32_t)) == CRYPT_SUCCESS);

    /* private key signature */
    ASSERT_TRUE(CRYPT_EAL_PkeySign(pkey, hashId, msg->x, msg->len, sign, &dataLen) == CRYPT_SUCCESS);

    /* public key verify */
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(pkey, hashId, msg->x, msg->len, sign, dataLen) == CRYPT_SUCCESS);

    newCtx = CRYPT_EAL_PkeyDupCtx(pkey);
    ASSERT_TRUE(newCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(newCtx, hashId, msg->x, msg->len, sign, &dataLen), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(newCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_BLINDING_FUNC_TC002
 * @title  RSA: Pkcsv15, Blinding, Signature.
 * @precon nan
 * @brief
 *    1. Create the context of the rsa algorithm, expected result 1
 *    2. Set private key, EMSA_PKCSV15 and CRYPT_RSA_BLINDING flag, expected result 2
 *    3. Initialize the drbg, expected result 3
 *    4. Signature, expected result 4
 *    5. Dup the context, and sign with new context, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS.
 *    5. Success.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_BLINDING_FUNC_TC002(int mdId, Hex *p, Hex *q, Hex *n, Hex *d, Hex *msg, int isProvider)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *newCtx = NULL;
    CRYPT_EAL_PkeyPrv prv = {0};
    uint8_t *signdata = NULL;
    uint32_t signLen;
    uint32_t flag = CRYPT_RSA_BLINDING;
    int32_t pkcsv15 = mdId;

    SetRsaPrvKey(&prv, n->x, n->len, d->x, d->len);
    prv.key.rsaPrv.p = p->x;
    prv.key.rsaPrv.pLen = p->len;
    prv.key.rsaPrv.q = q->x;
    prv.key.rsaPrv.qLen = q->len;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);  // Random numbers need to be generated during blinding.
    if (isProvider == 1) {
        ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_FLAG, (void *)&flag, sizeof(uint32_t)) == CRYPT_SUCCESS);

    /* Malloc signature buffer */
    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    signdata = (uint8_t *)calloc(1u, signLen);
    ASSERT_TRUE(signdata != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);

    newCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(newCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(newCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(newCtx);
    free(signdata);
    CRYPT_EAL_RandDeinit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_KEY_PAIR_CHECK_FUNC_TC001
 * @title  RSA: key pair check.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create two contexts(pubCtx, prvCtx) of the rsa algorithm, expected result 1
 *    2. Set public key for pubCtx, expected result 2
 *    3. Set private key for prvCtx, expected result 3
 *    4. Check whether the public key matches the private key, expected result 4
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. Return CRYPT_SUCCESS when expect is 1, CRYPT_RSA_NOR_VERIFY_FAIL otherwise.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_KEY_PAIR_CHECK_FUNC_TC001(Hex *n, Hex *e, Hex *d, int expect, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyPub pubKey = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};
    int expectRet = expect == 1 ? CRYPT_SUCCESS : CRYPT_RSA_NOR_VERIFY_FAIL;

    SetRsaPubKey(&pubKey, n->x, n->len, e->x, e->len);
    SetRsaPrvKey(&prvKey, n->x, n->len, d->x, d->len);

    TestMemInit();
    if (isProvider == 1) {
        pubCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        pubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    if (isProvider == 1) {
        prvCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
            CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else {
        prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    }
    ASSERT_TRUE(pubCtx != NULL && prvCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &prvKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), expectRet);

exit:
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
}
/* END_CASE */
