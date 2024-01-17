/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_XTS

#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes_xts.h"


#define MODE_XTS_BLOCKSIZE 16
#define SM4_XTS_POLYNOMIAL 0xE1
#define XTS_UPDATE_VALUES(l, i, o, len) \
    do { \
        (l) -= (len); \
        (i) += (len); \
        (o) += (len); \
    } while (false)

int32_t MODE_XTS_InitCtx(MODE_CipherCtx *ctx, EAL_CipherMethod *method)
{
    // The upper layer has checked the validity of the ctx and method.
    ctx->ciphCtx = BSL_SAL_Malloc(2 * method->ctxSize); // cipher context has 2 method contexts in xts mode
    if (ctx->ciphCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // Use 2 primitive contexts.
    (void)memset_s(ctx->ciphCtx, 2 * method->ctxSize, 0, 2 * method->ctxSize);
    // If the mode does not specify the blockSize, the blockSize value of algorithm will be assigned to the mode.
    if (ctx->blockSize == 0) {
        ctx->blockSize = method->blockSize;
    }
    ctx->algId = method->algId;
    ctx->ciphMeth = method;
    return CRYPT_SUCCESS;
}

static int32_t XtsCheckPara(const MODE_CipherCtx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // The key length supports only 256 bytes (32 bytes) and 512 bytes (64 bytes), corresponding to AES-128 and AES-256.
    if (len != 32 && len != 64) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_ERR_KEYLEN);
        return CRYPT_MODES_ERR_KEYLEN;
    }
    return CRYPT_SUCCESS;
}

int32_t MODE_XTS_SetEncryptKey(MODE_CipherCtx *ctx, const uint8_t *key, uint32_t len)
{
    int32_t ret = XtsCheckPara(ctx, key, len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t keyLen = len >> 1;
    if (memcmp(key, key + keyLen, keyLen) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_ERR_KEY);
        return CRYPT_MODES_ERR_KEY;
    }
    ret = ctx->ciphMeth->setEncryptKey(ctx->ciphCtx, key, keyLen); // key1
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ctx->ciphMeth->setEncryptKey((uint8_t*)ctx->ciphCtx + ctx->ciphMeth->ctxSize, key + keyLen, keyLen); // key2
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t MODE_XTS_SetDecryptKey(MODE_CipherCtx *ctx, const uint8_t *key, uint32_t len)
{
    int32_t ret = XtsCheckPara(ctx, key, len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t keyLen = len >> 1;
    if (memcmp(key + keyLen, key, keyLen) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_ERR_KEY);
        return CRYPT_MODES_ERR_KEY;
    }
    ret = ctx->ciphMeth->setEncryptKey((uint8_t*)ctx->ciphCtx + ctx->ciphMeth->ctxSize, key + keyLen, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ctx->ciphMeth->setDecryptKey(ctx->ciphCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

void GF128MulGm(uint8_t *a, uint32_t len)
{
    uint8_t in = 0;
    uint8_t out = 0;

    for (uint32_t j = 0; j < len; j++) {
        out = (a[j] << 7) & 0x80;
        a[j] = ((a[j] >> 1u) + in) & 0xFFu;
        in = out;
    }
    if (out > 0) {
        a[0] ^= SM4_XTS_POLYNOMIAL; // reverse (10000111)2
    }
}

int32_t BlockCrypt(MODE_CipherCtx *ctx, const uint8_t *in, const uint8_t *t, uint8_t *pp, bool enc)
{
    int32_t ret;
    uint32_t blockSize = ctx->blockSize;
    DATA64_XOR(in, t, pp, blockSize);

    if (enc) {
        ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, pp, pp, blockSize);
    } else {
        ret = ctx->ciphMeth->decrypt(ctx->ciphCtx, pp, pp, blockSize);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    DATA64_XOR(pp, t, pp, blockSize);

    return CRYPT_SUCCESS;
}

int32_t BlocksCrypt(MODE_CipherCtx *ctx, const uint8_t **in, uint8_t **out, uint32_t *tmpLen,
    bool enc)
{
    int32_t ret;
    uint32_t blockSize = ctx->blockSize;
    const uint8_t *tmpIn = *in;
    uint8_t *tmpOut = *out;
    while (*tmpLen >= 2 * blockSize) {  // If the value is greater than blockSize * 2, process the tmpIn.
        ret = BlockCrypt(ctx, tmpIn, ctx->iv, tmpOut, enc);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }

        XTS_UPDATE_VALUES(*tmpLen, tmpIn, tmpOut, blockSize);
        GF128MulGm(ctx->iv, blockSize);
    }
    *in = tmpIn;
    *out = tmpOut;
    return CRYPT_SUCCESS;
}

int32_t MODE_XTS_Encrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    int32_t ret;
    uint32_t i;
    uint8_t pp[MODE_XTS_BLOCKSIZE];
    uint32_t tmpLen = len;
    const uint8_t *tmpIn = in;
    uint8_t *tmpOut = out;
    uint8_t *lastBlock = NULL;
    uint32_t blockSize = ctx->blockSize;

    if (len < blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }
    if (ctx->algId != CRYPT_SYM_SM4) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_METHODS_NOT_SUPPORT);
        return CRYPT_MODES_METHODS_NOT_SUPPORT;
    }
    ret = BlocksCrypt(ctx, &tmpIn, &tmpOut, &tmpLen, true);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Encryption
    ret = BlockCrypt(ctx, tmpIn, ctx->iv, tmpOut, true);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    XTS_UPDATE_VALUES(tmpLen, tmpIn, tmpOut, blockSize);
    // If len is an integer multiple of blockSize, the subsequent calculations is not required.
    if (tmpLen == 0) {
        GF128MulGm(ctx->iv, blockSize);
        return CRYPT_SUCCESS;
    }
    GF128MulGm(ctx->iv, blockSize);

    lastBlock = tmpOut - blockSize;
    // Process the subsequent two pieces of data.
    for (i = 0; i < tmpLen; i++) {
        tmpOut[i] = lastBlock[i];
        pp[i] = tmpIn[i];
    }

    for (i = tmpLen; i < blockSize; i++) {
        pp[i] = lastBlock[i];
    }
    ret = BlockCrypt(ctx, pp, ctx->iv, pp, true);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // set c m-1
    tmpOut -= blockSize;
    if (memcpy_s(tmpOut, blockSize + tmpLen, pp, blockSize) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

int32_t MODE_XTS_Decrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    int32_t ret;
    uint8_t pp[MODE_XTS_BLOCKSIZE], t2[MODE_XTS_BLOCKSIZE]; // xts blocksize MODE_XTS_BLOCKSIZE
    uint32_t i;
    uint32_t tmpLen = len;
    const uint8_t *tmpIn = in;
    uint32_t blockSize = ctx->blockSize;
    uint8_t *tmpOut = out;

    if (len < blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }
    if (ctx->algId != CRYPT_SYM_SM4) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_METHODS_NOT_SUPPORT);
        return CRYPT_MODES_METHODS_NOT_SUPPORT;
    }
    ret = BlocksCrypt(ctx, &tmpIn, &tmpOut, &tmpLen, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // If len is an integer multiple of blockSize, the subsequent calculations is not required.
    if (tmpLen == blockSize) {
        ret = BlockCrypt(ctx, tmpIn, ctx->iv, tmpOut, false);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        GF128MulGm(ctx->iv, blockSize);
        return CRYPT_SUCCESS;
    }

    (void)memcpy_s(t2, MODE_XTS_BLOCKSIZE, ctx->iv, blockSize);

    GF128MulGm(ctx->iv, blockSize);

    ret = BlockCrypt(ctx, tmpIn, ctx->iv, pp, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    tmpLen -= blockSize;

    for (i = 0; i < tmpLen; i++) {
        tmpOut[i + blockSize] = pp[i];
        pp[i] = tmpIn[i + blockSize];
    }

    ret = BlockCrypt(ctx, pp, t2, pp, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (memcpy_s(tmpOut, blockSize + tmpLen, pp, blockSize) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

void MODE_XTS_Clean(MODE_CipherCtx *ctx)
{
    BSL_SAL_CleanseData((void *)(ctx->iv), MODES_MAX_IV_LENGTH);
    ctx->ciphMeth->clean(ctx->ciphCtx);
    ctx->ciphMeth->clean((void *)((uintptr_t)ctx->ciphCtx + ctx->ciphMeth->ctxSize));
}

static int32_t SetIv(MODE_CipherCtx *ctx, uint8_t *val, uint32_t len)
{
    int32_t ret;
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != ctx->blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_IVLEN_ERROR);
        return CRYPT_MODES_IVLEN_ERROR;
    }
    if (memcpy_s(ctx->iv, MODES_MAX_IV_LENGTH, (uint8_t*)val, len) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }

    // Use key2 and i to encrypt to obtain the tweak.
    ret = ctx->ciphMeth->encrypt((uint8_t*)ctx->ciphCtx + ctx->ciphMeth->ctxSize, ctx->iv, ctx->iv, ctx->blockSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static int32_t GetIv(MODE_CipherCtx *ctx, uint8_t *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != ctx->blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }
    if (memcpy_s(val, len, ctx->iv, ctx->blockSize) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

int32_t MODE_XTS_Ctrl(MODE_CipherCtx *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_SET_IV:
            return SetIv(ctx, (uint8_t *)val, len);
        case CRYPT_CTRL_GET_IV:
            return GetIv(ctx, (uint8_t *)val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MODES_METHODS_NOT_SUPPORT);
            return CRYPT_MODES_METHODS_NOT_SUPPORT;
    }
}
#endif // HITLS_CRYPTO_XTS
