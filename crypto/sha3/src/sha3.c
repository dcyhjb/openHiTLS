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
#ifdef HITLS_CRYPTO_SHA3

#include <stdlib.h>
#include "securec.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "sha3_core.h"
#include "crypt_sha3.h"


static int32_t CRYPT_SHA3_Init(CRYPT_SHA3_Ctx *ctx, uint32_t mdSize, uint32_t blockSize, uint8_t padChr)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)memset_s(ctx, sizeof(CRYPT_SHA3_Ctx), 0, sizeof(CRYPT_SHA3_Ctx));
    ctx->mdSize = mdSize;
    ctx->padChr = padChr;
    ctx->blockSize = blockSize;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_SHA3_Update(CRYPT_SHA3_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    if (ctx == NULL || (in == NULL && len != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len == 0) {
        return CRYPT_SUCCESS;
    }
    const uint8_t *data = in;
    uint32_t left = ctx->blockSize - ctx->num;
    uint32_t dataLen = len;

    if (ctx->num != 0) {
        if (dataLen < left) {
            (void)memcpy_s(ctx->buf + ctx->num, left, data, dataLen);
            ctx->num += dataLen;
            return CRYPT_SUCCESS;
        }

        // When the external input data is greater than the remaining space of the block,
        // copy the data of the remaining space.
        (void)memcpy_s(ctx->buf + ctx->num, left, data, left);
        SHA3_Absorb(ctx->state, ctx->buf, ctx->blockSize, ctx->blockSize);
        dataLen -= left;
        data += left;
        ctx->num = 0;
    }

    data = SHA3_Absorb(ctx->state, data, dataLen, ctx->blockSize);
    dataLen = len - (data - in);
    if (dataLen != 0) {
        // copy the remaining data to the cache array
        (void)memcpy_s(ctx->buf, ctx->blockSize, data, dataLen);
        ctx->num = dataLen;
    }

    return CRYPT_SUCCESS;
}

static int32_t CRYPT_SHA3_Final(CRYPT_SHA3_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    if (ctx == NULL || out == NULL || len == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (*len < ctx->mdSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_SHA3_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_SHA3_OUT_BUFF_LEN_NOT_ENOUGH;
    }

    uint32_t left = ctx->blockSize - ctx->num;
    uint32_t outLen = (ctx->mdSize == 0) ? *len : ctx->mdSize;
    (void)memset_s(ctx->buf + ctx->num, left, 0, left);
    ctx->buf[ctx->num] = ctx->padChr;
    ctx->buf[ctx->blockSize - 1] |= 0x80; // 0x80 is the last 1 of pad 10*1 mode

    (void)SHA3_Absorb(ctx->state, ctx->buf, ctx->blockSize, ctx->blockSize);
    SHA3_Squeeze(ctx->state, out, outLen, ctx->blockSize);
    *len = outLen;
    return CRYPT_SUCCESS;
}

static void CRYPT_SHA3_Deinit(CRYPT_SHA3_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return;
    }
    BSL_SAL_CleanseData(ctx, sizeof(CRYPT_SHA3_Ctx));
}

static int32_t CRYPT_SHA3_CopyCtx(CRYPT_SHA3_Ctx *dst, CRYPT_SHA3_Ctx *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memcpy_s(dst, sizeof(CRYPT_SHA3_Ctx), src, sizeof(CRYPT_SHA3_Ctx));
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SHA3_224_Init(CRYPT_SHA3_224_Ctx *ctx)
{
    // 0x06 is SHA3 padding character, see https://keccak.team/keccak_specs_summary.html
    return CRYPT_SHA3_Init(ctx, CRYPT_SHA3_224_DIGESTSIZE, CRYPT_SHA3_224_BLOCKSIZE, 0x06);
}

int32_t CRYPT_SHA3_256_Init(CRYPT_SHA3_256_Ctx *ctx)
{
    // 0x06 is SHA3 padding character, see https://keccak.team/keccak_specs_summary.html
    return CRYPT_SHA3_Init(ctx, CRYPT_SHA3_256_DIGESTSIZE, CRYPT_SHA3_256_BLOCKSIZE, 0x06);
}

int32_t CRYPT_SHA3_384_Init(CRYPT_SHA3_384_Ctx *ctx)
{
    // 0x06 is SHA3 padding character, see https://keccak.team/keccak_specs_summary.html
    return CRYPT_SHA3_Init(ctx, CRYPT_SHA3_384_DIGESTSIZE, CRYPT_SHA3_384_BLOCKSIZE, 0x06);
}

int32_t CRYPT_SHA3_512_Init(CRYPT_SHA3_512_Ctx *ctx)
{
    // 0x06 is SHA3 padding character, see https://keccak.team/keccak_specs_summary.html
    return CRYPT_SHA3_Init(ctx, CRYPT_SHA3_512_DIGESTSIZE, CRYPT_SHA3_512_BLOCKSIZE, 0x06);
}

int32_t CRYPT_SHAKE128_Init(CRYPT_SHAKE128_Ctx *ctx)
{
    // 0x1f is SHA3 padding character, see https://keccak.team/keccak_specs_summary.html
    return CRYPT_SHA3_Init(ctx, 0, CRYPT_SHAKE128_BLOCKSIZE, 0x1F);
}

int32_t CRYPT_SHAKE256_Init(CRYPT_SHAKE256_Ctx *ctx)
{
    // 0x1f is SHA3 padding character, see https://keccak.team/keccak_specs_summary.html
    return CRYPT_SHA3_Init(ctx, 0, CRYPT_SHAKE256_BLOCKSIZE, 0x1F);
}

int32_t CRYPT_SHA3_224_Update(CRYPT_SHA3_224_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    return CRYPT_SHA3_Update(ctx, in, len);
}

int32_t CRYPT_SHA3_256_Update(CRYPT_SHA3_256_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    return CRYPT_SHA3_Update(ctx, in, len);
}

int32_t CRYPT_SHA3_384_Update(CRYPT_SHA3_384_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    return CRYPT_SHA3_Update(ctx, in, len);
}

int32_t CRYPT_SHA3_512_Update(CRYPT_SHA3_512_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    return CRYPT_SHA3_Update(ctx, in, len);
}

int32_t CRYPT_SHAKE128_Update(CRYPT_SHAKE128_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    return CRYPT_SHA3_Update(ctx, in, len);
}

int32_t CRYPT_SHAKE256_Update(CRYPT_SHAKE256_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    return CRYPT_SHA3_Update(ctx, in, len);
}

int32_t CRYPT_SHA3_224_Final(CRYPT_SHA3_224_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    return CRYPT_SHA3_Final(ctx, out, len);
}

int32_t CRYPT_SHA3_256_Final(CRYPT_SHA3_256_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    return CRYPT_SHA3_Final(ctx, out, len);
}

int32_t CRYPT_SHA3_384_Final(CRYPT_SHA3_384_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    return CRYPT_SHA3_Final(ctx, out, len);
}

int32_t CRYPT_SHA3_512_Final(CRYPT_SHA3_512_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    return CRYPT_SHA3_Final(ctx, out, len);
}

int32_t CRYPT_SHAKE128_Final(CRYPT_SHAKE128_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    return CRYPT_SHA3_Final(ctx, out, len);
}

int32_t CRYPT_SHAKE256_Final(CRYPT_SHAKE256_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    return CRYPT_SHA3_Final(ctx, out, len);
}

void CRYPT_SHA3_224_Deinit(CRYPT_SHA3_224_Ctx *ctx)
{
    CRYPT_SHA3_Deinit(ctx);
}

void CRYPT_SHA3_256_Deinit(CRYPT_SHA3_256_Ctx *ctx)
{
    CRYPT_SHA3_Deinit(ctx);
}

void CRYPT_SHA3_384_Deinit(CRYPT_SHA3_384_Ctx *ctx)
{
    CRYPT_SHA3_Deinit(ctx);
}

void CRYPT_SHA3_512_Deinit(CRYPT_SHA3_512_Ctx *ctx)
{
    CRYPT_SHA3_Deinit(ctx);
}

void CRYPT_SHAKE128_Deinit(CRYPT_SHAKE128_Ctx *ctx)
{
    CRYPT_SHA3_Deinit(ctx);
}

void CRYPT_SHAKE256_Deinit(CRYPT_SHAKE256_Ctx *ctx)
{
    CRYPT_SHA3_Deinit(ctx);
}

int32_t CRYPT_SHA3_224_CopyCtx(CRYPT_SHA3_224_Ctx *dst, CRYPT_SHA3_224_Ctx *src)
{
    return CRYPT_SHA3_CopyCtx(dst, src);
}

int32_t CRYPT_SHA3_256_CopyCtx(CRYPT_SHA3_256_Ctx *dst, CRYPT_SHA3_256_Ctx *src)
{
    return CRYPT_SHA3_CopyCtx(dst, src);
}

int32_t CRYPT_SHA3_384_CopyCtx(CRYPT_SHA3_384_Ctx *dst, CRYPT_SHA3_384_Ctx *src)
{
    return CRYPT_SHA3_CopyCtx(dst, src);
}

int32_t CRYPT_SHA3_512_CopyCtx(CRYPT_SHA3_512_Ctx *dst, CRYPT_SHA3_512_Ctx *src)
{
    return CRYPT_SHA3_CopyCtx(dst, src);
}

#endif // HITLS_CRYPTO_SHA3
