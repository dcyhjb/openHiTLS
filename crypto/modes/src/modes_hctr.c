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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HCTR

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_modes_hctr.h"
#include "modes_local.h"

#define HCTR_MIN_BLOCKSIZE 16
#define HCTR_MAX_KEY_LEN 64

typedef struct ModesHctrCtx {
    int32_t algId;
    MODES_CipherCommonCtx commonCtx;
    uint8_t *cache;
    uint32_t cacheLen;
    uint32_t cacheCap;
    uint8_t tweak[MODES_MAX_IV_LENGTH];
    uint32_t tweakLen;
    uint8_t hashKey[GCM_BLOCKSIZE];
    MODES_GCM_GF128 hTable[16];
    uint8_t key[HCTR_MAX_KEY_LEN];
    uint32_t keyLen;
    bool enc;
} MODES_HCTR_Ctx;

static void HctrCleanBuffer(MODES_HCTR_Ctx *ctx)
{
    if (ctx->cache != NULL) {
        BSL_SAL_CleanseData(ctx->cache, ctx->cacheLen);
        BSL_SAL_Free(ctx->cache);
        ctx->cache = NULL;
    }
    ctx->cacheLen = 0;
    ctx->cacheCap = 0;
}

static int32_t HctrEnsureCapacity(MODES_HCTR_Ctx *ctx, uint32_t newCap)
{
    if (newCap == 0) {
        return CRYPT_SUCCESS;
    }
    if (ctx->cacheCap >= newCap) {
        return CRYPT_SUCCESS;
    }
    uint32_t alloc = ctx->cacheCap == 0 ? newCap : ctx->cacheCap;
    while (alloc < newCap) {
        if (alloc > UINT32_MAX / 2) {
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_TOO_LONG);
            return CRYPT_EAL_BUFF_LEN_TOO_LONG;
        }
        alloc <<= 1;
    }
    uint8_t *tmp = (uint8_t *)BSL_SAL_Realloc(ctx->cache, alloc, ctx->cacheCap);
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->cache = tmp;
    ctx->cacheCap = alloc;
    return CRYPT_SUCCESS;
}

static void HctrCalcHash(const MODES_HCTR_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t hash[GCM_BLOCKSIZE])
{
    (void)memset_s(hash, GCM_BLOCKSIZE, 0, GCM_BLOCKSIZE);
    if (dataLen > 0) {
        uint32_t blockLen = dataLen & GCM_BLOCK_MASK;
        if (blockLen > 0) {
            GcmHashMultiBlock(hash, ctx->hTable, data, blockLen);
        }
        uint32_t rem = dataLen - blockLen;
        if (rem > 0) {
            uint8_t tmp[GCM_BLOCKSIZE] = {0};
            (void)memcpy_s(tmp, GCM_BLOCKSIZE, data + blockLen, rem);
            GcmHashMultiBlock(hash, ctx->hTable, tmp, GCM_BLOCKSIZE);
            BSL_SAL_CleanseData(tmp, sizeof(tmp));
        }
    }
    if (ctx->tweakLen > 0) {
        uint32_t blockLen = ctx->tweakLen & GCM_BLOCK_MASK;
        if (blockLen > 0) {
            GcmHashMultiBlock(hash, ctx->hTable, ctx->tweak, blockLen);
        }
        uint32_t rem = ctx->tweakLen - blockLen;
        if (rem > 0) {
            uint8_t tmp[GCM_BLOCKSIZE] = {0};
            (void)memcpy_s(tmp, GCM_BLOCKSIZE, ctx->tweak + blockLen, rem);
            GcmHashMultiBlock(hash, ctx->hTable, tmp, GCM_BLOCKSIZE);
            BSL_SAL_CleanseData(tmp, sizeof(tmp));
        }
    }
    uint8_t lenBlock[GCM_BLOCKSIZE] = {0};
    Uint64ToBeBytes(((uint64_t)dataLen) << 3, lenBlock);
    Uint64ToBeBytes(((uint64_t)ctx->tweakLen) << 3, lenBlock + sizeof(uint64_t));
    GcmHashMultiBlock(hash, ctx->hTable, lenBlock, GCM_BLOCKSIZE);
    BSL_SAL_CleanseData(lenBlock, sizeof(lenBlock));
}

static int32_t HctrCtrCrypt(MODES_HCTR_Ctx *ctx, const uint8_t *in, uint32_t inLen,
    uint8_t *out, const uint8_t counter[GCM_BLOCKSIZE])
{
    if (inLen == 0) {
        return CRYPT_SUCCESS;
    }
    uint8_t ctr[GCM_BLOCKSIZE];
    uint8_t stream[GCM_BLOCKSIZE];
    (void)memcpy_s(ctr, GCM_BLOCKSIZE, counter, GCM_BLOCKSIZE);
    uint32_t offset = 0;
    while (inLen - offset >= GCM_BLOCKSIZE) {
        int32_t ret = ctx->commonCtx.ciphMeth->encryptBlock(ctx->commonCtx.ciphCtx, ctr, stream, GCM_BLOCKSIZE);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_CleanseData(stream, sizeof(stream));
            BSL_SAL_CleanseData(ctr, sizeof(ctr));
            return ret;
        }
        DATA64_XOR(in + offset, stream, out + offset, GCM_BLOCKSIZE);
        offset += GCM_BLOCKSIZE;
        MODE_IncCounter(ctr, GCM_BLOCKSIZE);
    }
    if (offset < inLen) {
        int32_t ret = ctx->commonCtx.ciphMeth->encryptBlock(ctx->commonCtx.ciphCtx, ctr, stream, GCM_BLOCKSIZE);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_CleanseData(stream, sizeof(stream));
            BSL_SAL_CleanseData(ctr, sizeof(ctr));
            return ret;
        }
        for (uint32_t i = 0; i < inLen - offset; i++) {
            out[offset + i] = in[offset + i] ^ stream[i];
        }
    }
    BSL_SAL_CleanseData(stream, sizeof(stream));
    BSL_SAL_CleanseData(ctr, sizeof(ctr));
    return CRYPT_SUCCESS;
}

MODES_HCTR_Ctx *MODES_HCTR_NewCtx(int32_t algId)
{
    const EAL_SymMethod *method = EAL_GetSymMethod(algId);
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    if (method->blockSize < HCTR_MIN_BLOCKSIZE || method->blockSize > GCM_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    MODES_HCTR_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(MODES_HCTR_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->commonCtx.ciphCtx = BSL_SAL_Calloc(1, method->ctxSize);
    if (ctx->commonCtx.ciphCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(ctx);
        return NULL;
    }
    ctx->commonCtx.ciphMeth = method;
    ctx->commonCtx.blockSize = method->blockSize;
    ctx->algId = algId;
    ctx->enc = true;
    return ctx;
}

MODES_HCTR_Ctx *MODES_HCTR_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    return MODES_HCTR_NewCtx(algId);
}

static int32_t HctrSetKey(MODES_HCTR_Ctx *ctx, const uint8_t *key, uint32_t keyLen)
{
    if (key == NULL || keyLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (keyLen > HCTR_MAX_KEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_ERR_KEYLEN);
        return CRYPT_MODES_ERR_KEYLEN;
    }
    int32_t ret = ctx->commonCtx.ciphMeth->setEncryptKey(ctx->commonCtx.ciphCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy_s(ctx->key, sizeof(ctx->key), key, keyLen);
    ctx->keyLen = keyLen;
    return CRYPT_SUCCESS;
}

static int32_t HctrSetTweak(MODES_HCTR_Ctx *ctx, const uint8_t *iv, uint32_t ivLen)
{
    if ((iv == NULL && ivLen != 0) || ivLen > MODES_MAX_IV_LENGTH) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_IVLEN_ERROR);
        return CRYPT_MODES_IVLEN_ERROR;
    }
    if (ivLen == 0) {
        (void)memset_s(ctx->tweak, sizeof(ctx->tweak), 0, sizeof(ctx->tweak));
        ctx->tweakLen = 0;
        return CRYPT_SUCCESS;
    }
    if (ivLen != ctx->commonCtx.blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_IVLEN_ERROR);
        return CRYPT_MODES_IVLEN_ERROR;
    }
    (void)memcpy_s(ctx->tweak, sizeof(ctx->tweak), iv, ivLen);
    ctx->tweakLen = ivLen;
    return CRYPT_SUCCESS;
}

int32_t MODES_HCTR_InitCtx(MODES_HCTR_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen,
    const uint8_t *iv, uint32_t ivLen, bool enc)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = HctrSetKey(modeCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = HctrSetTweak(modeCtx, iv, ivLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint8_t zero[GCM_BLOCKSIZE] = {0};
    ret = modeCtx->commonCtx.ciphMeth->encryptBlock(modeCtx->commonCtx.ciphCtx, zero, modeCtx->hashKey, GCM_BLOCKSIZE);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    GcmTableGen4bit(modeCtx->hashKey, modeCtx->hTable);
    HctrCleanBuffer(modeCtx);
    modeCtx->enc = enc;
    return CRYPT_SUCCESS;
}

int32_t MODES_HCTR_InitCtxEx(MODES_HCTR_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen,
    const uint8_t *iv, uint32_t ivLen, void *param, bool enc)
{
    (void)param;
    return MODES_HCTR_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
}

int32_t MODES_HCTR_Update(MODES_HCTR_Ctx *modeCtx, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    if (modeCtx == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (inLen != 0 && in == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)out;
    if (modeCtx->cacheLen + inLen < modeCtx->cacheLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_TOO_LONG);
        return CRYPT_EAL_BUFF_LEN_TOO_LONG;
    }
    int32_t ret = HctrEnsureCapacity(modeCtx, modeCtx->cacheLen + inLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (inLen > 0) {
        (void)memcpy_s(modeCtx->cache + modeCtx->cacheLen, modeCtx->cacheCap - modeCtx->cacheLen, in, inLen);
        modeCtx->cacheLen += inLen;
    }
    *outLen = 0;
    return CRYPT_SUCCESS;
}

int32_t MODES_HCTR_Final(MODES_HCTR_Ctx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    if (modeCtx == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (modeCtx->cacheLen < modeCtx->commonCtx.blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }
    if (*outLen < modeCtx->cacheLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }
    uint32_t blockSize = modeCtx->commonCtx.blockSize;
    const uint8_t *input = modeCtx->cache;
    const uint8_t *rest = input + blockSize;
    uint32_t restLen = modeCtx->cacheLen - blockSize;
    uint8_t delta[GCM_BLOCKSIZE];
    HctrCalcHash(modeCtx, rest, restLen, delta);
    uint8_t tmp[GCM_BLOCKSIZE];
    int32_t ret;
    if (modeCtx->enc) {
        DATA64_XOR(input, delta, tmp, blockSize);
        ret = modeCtx->commonCtx.ciphMeth->encryptBlock(modeCtx->commonCtx.ciphCtx, tmp, tmp, blockSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_CleanseData(tmp, sizeof(tmp));
            BSL_SAL_CleanseData(delta, sizeof(delta));
            return ret;
        }
        DATA64_XOR(tmp, delta, out, blockSize);
        ret = HctrCtrCrypt(modeCtx, rest, restLen, out + blockSize, out);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(tmp, sizeof(tmp));
            BSL_SAL_CleanseData(delta, sizeof(delta));
            return ret;
        }
    } else {
        ret = HctrCtrCrypt(modeCtx, rest, restLen, out + blockSize, input);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(delta, sizeof(delta));
            return ret;
        }
        DATA64_XOR(input, delta, tmp, blockSize);
        ret = modeCtx->commonCtx.ciphMeth->setDecryptKey(modeCtx->commonCtx.ciphCtx, modeCtx->key, modeCtx->keyLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_CleanseData(tmp, sizeof(tmp));
            BSL_SAL_CleanseData(delta, sizeof(delta));
            return ret;
        }
        ret = modeCtx->commonCtx.ciphMeth->decryptBlock(modeCtx->commonCtx.ciphCtx, tmp, tmp, blockSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_CleanseData(tmp, sizeof(tmp));
            BSL_SAL_CleanseData(delta, sizeof(delta));
            return ret;
        }
        DATA64_XOR(tmp, delta, out, blockSize);
        (void)modeCtx->commonCtx.ciphMeth->setEncryptKey(modeCtx->commonCtx.ciphCtx, modeCtx->key, modeCtx->keyLen);
    }
    *outLen = modeCtx->cacheLen;
    BSL_SAL_CleanseData(tmp, sizeof(tmp));
    BSL_SAL_CleanseData(delta, sizeof(delta));
    HctrCleanBuffer(modeCtx);
    return CRYPT_SUCCESS;
}

int32_t MODES_HCTR_DeInitCtx(MODES_HCTR_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    HctrCleanBuffer(modeCtx);
    if (modeCtx->commonCtx.ciphMeth != NULL && modeCtx->commonCtx.ciphMeth->cipherDeInitCtx != NULL) {
        (void)modeCtx->commonCtx.ciphMeth->cipherDeInitCtx(modeCtx->commonCtx.ciphCtx);
    }
    (void)memset_s(modeCtx->key, sizeof(modeCtx->key), 0, sizeof(modeCtx->key));
    (void)memset_s(modeCtx->hashKey, sizeof(modeCtx->hashKey), 0, sizeof(modeCtx->hashKey));
    (void)memset_s(modeCtx->tweak, sizeof(modeCtx->tweak), 0, sizeof(modeCtx->tweak));
    modeCtx->keyLen = 0;
    modeCtx->tweakLen = 0;
    return CRYPT_SUCCESS;
}

int32_t MODES_HCTR_Ctrl(MODES_HCTR_Ctx *modeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_CTRL_SET_IV:
            return HctrSetTweak(modeCtx, (const uint8_t *)val, valLen);
        case CRYPT_CTRL_GET_IV:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            if (valLen < modeCtx->tweakLen) {
                BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
                return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
            }
            if (modeCtx->tweakLen > 0) {
                (void)memcpy_s(val, valLen, modeCtx->tweak, modeCtx->tweakLen);
            }
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_GET_BLOCKSIZE:
            if (val == NULL || valLen != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = modeCtx->commonCtx.blockSize;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TYPE_ERROR);
            return CRYPT_MODES_CTRL_TYPE_ERROR;
    }
}

void MODES_HCTR_FreeCtx(MODES_HCTR_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        return;
    }
    HctrCleanBuffer(modeCtx);
    if (modeCtx->commonCtx.ciphCtx != NULL) {
        if (modeCtx->commonCtx.ciphMeth != NULL && modeCtx->commonCtx.ciphMeth->cipherDeInitCtx != NULL) {
            (void)modeCtx->commonCtx.ciphMeth->cipherDeInitCtx(modeCtx->commonCtx.ciphCtx);
        }
        BSL_SAL_CleanseData(modeCtx->commonCtx.ciphCtx, modeCtx->commonCtx.ciphMeth->ctxSize);
        BSL_SAL_Free(modeCtx->commonCtx.ciphCtx);
    }
    BSL_SAL_Free(modeCtx);
}

#endif
