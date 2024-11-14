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
#ifdef HITLS_CRYPTO_ECDH

#include <stdbool.h>
#include "crypt_errno.h"
#include "crypt_types.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_bn.h"
#include "crypt_ecc.h"
#include "crypt_ecc_pkey.h"
#include "crypt_ecdh.h"
#include "sal_atomic.h"

CRYPT_ECDH_Ctx *CRYPT_ECDH_NewCtx(void)
{
    ECC_Pkey *ctx = BSL_SAL_Calloc(1u, sizeof(ECC_Pkey));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->useCofactorMode = true;
    ctx->pointFormat = CRYPT_POINT_UNCOMPRESSED;    // the point format is uncompressed by default
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

CRYPT_ECDH_Ctx *CRYPT_ECDH_DupCtx(CRYPT_ECDH_Ctx *ctx)
{
    return ECC_DupCtx(ctx);
}

void CRYPT_ECDH_FreeCtx(CRYPT_ECDH_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ECC_FreeCtx(ctx);
    return;
}

CRYPT_EcdhPara *CRYPT_ECDH_NewParaById(CRYPT_PKEY_ParaId id)
{
    return ECC_NewPara(id);
}

CRYPT_EcdhPara *CRYPT_ECDH_NewPara(const CRYPT_EccPara *eccPara)
{
    if (eccPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_PKEY_ParaId id = ECC_GetCurveId(eccPara);
    if (id == CRYPT_PKEY_PARAID_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_ERR_PARA);
        return NULL;
    }
    return CRYPT_ECDH_NewParaById(id);
}

CRYPT_PKEY_ParaId CRYPT_ECDH_GetParaId(const CRYPT_ECDH_Ctx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_PKEY_PARAID_MAX;
    }
    return ECC_GetParaId(ctx->para);
}

void CRYPT_ECDH_FreePara(CRYPT_EcdhPara *para)
{
    ECC_FreePara(para);
}

int32_t CRYPT_ECDH_GetPara(const CRYPT_ECDH_Ctx *ctx, CRYPT_EccPara *para)
{
    return ECC_GetPara(ctx, para);
}

int32_t CRYPT_ECDH_SetPara(CRYPT_ECDH_Ctx *ctx, const CRYPT_EcdhPara *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    CRYPT_EcdhPara *dstPara = ECC_DupPara(para);
    if (dstPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    // updating public and private keys
    BN_Destroy(ctx->prvkey);
    ECC_FreePoint(ctx->pubkey);
    ctx->prvkey = NULL;
    ctx->pubkey = NULL;

    ECC_FreePara(ctx->para);
    ctx->para = dstPara;

    return CRYPT_SUCCESS;
}

uint32_t CRYPT_ECDH_GetBits(const CRYPT_ECDH_Ctx *ctx)
{
    return ECC_PkeyGetBits(ctx);
}

int32_t CRYPT_ECDH_SetPrvKey(CRYPT_ECDH_Ctx *ctx, const CRYPT_EcdhPrv *prv)
{
    return ECC_PkeySetPrvKey(ctx, prv);
}

int32_t CRYPT_ECDH_SetPubKey(CRYPT_ECDH_Ctx *ctx, const CRYPT_EcdhPub *pub)
{
    return ECC_PkeySetPubKey(ctx, pub);
}

int32_t CRYPT_ECDH_GetPrvKey(const CRYPT_ECDH_Ctx *ctx, CRYPT_EcdhPrv *prv)
{
    return ECC_PkeyGetPrvKey(ctx, prv);
}

int32_t CRYPT_ECDH_GetPubKey(const CRYPT_ECDH_Ctx *ctx, CRYPT_EcdhPub *pub)
{
    return ECC_PkeyGetPubKey(ctx, pub);
}

int32_t CRYPT_ECDH_Gen(CRYPT_ECDH_Ctx *ctx)
{
    return ECC_PkeyGen(ctx);
}

static int32_t ComputeShareKeyInputCheck(const CRYPT_ECDH_Ctx *ctx, const CRYPT_ECDH_Ctx *pubKey,
    const uint8_t *shareKey, const uint32_t *shareKeyLen)
{
    if ((ctx == NULL) || (pubKey == NULL) || (shareKey == NULL) || (shareKeyLen == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if ((ctx->prvkey == NULL) || (pubKey->pubkey == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECDH_ERR_EMPTY_KEY);
        return CRYPT_ECDH_ERR_EMPTY_KEY;
    }

    // only the cofactor which value is 1 is supported currently
    BN_BigNum *paraH = ECC_GetParaH(ctx->para);
    if (paraH == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (BN_IsOne(paraH) != true) {
        BN_Destroy(paraH);
        BSL_ERR_PUSH_ERROR(CRYPT_ECDH_ERR_INVALID_COFACTOR);
        return CRYPT_ECDH_ERR_INVALID_COFACTOR;
    }
    BN_Destroy(paraH);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_ECDH_ComputeShareKey(const CRYPT_ECDH_Ctx *ctx, const CRYPT_ECDH_Ctx *pubKey,
    uint8_t *shareKey, uint32_t *shareKeyLen)
{
    int32_t ret = ComputeShareKeyInputCheck(ctx, pubKey, shareKey, shareKeyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ECC_Point *sharePoint = NULL;
    CRYPT_Data shareKeyX = {shareKey, *shareKeyLen};
    BN_BigNum *tmpPrvkey = BN_Dup(ctx->prvkey);
    sharePoint = ECC_NewPoint(ctx->para);
    if ((tmpPrvkey == NULL) || (sharePoint == NULL)) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    /** When the cofactor mode is enabled, pubkey = prvkey * h * G. When h is 1, no calculation is required.
     *  Currently, the cofactor of the prime curve is only 1, and no related calculation is required.
     */
    ret = ECC_PointMul(ctx->para, sharePoint, ctx->prvkey, pubKey->pubkey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = ECC_PointCheck(sharePoint);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = ECC_GetPoint(ctx->para, sharePoint, &shareKeyX, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    *shareKeyLen = shareKeyX.len;

ERR:
    ECC_FreePoint(sharePoint);
    BN_Destroy(tmpPrvkey);
    return ret;
}

int32_t CRYPT_ECDH_Ctrl(CRYPT_ECDH_Ctx *ctx, CRYPT_PkeyCtrl opt, void *val, uint32_t len)
{
    return ECC_PkeyCtrl(ctx, opt, val, len);
}

int32_t CRYPT_ECDH_Cmp(const CRYPT_ECDH_Ctx *a, const CRYPT_ECDH_Ctx *b)
{
    return ECC_PkeyCmp(a, b);
}

int32_t CRYPT_ECDH_GetSecBits(const CRYPT_ECDH_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return ECC_GetSecBits(ctx->para);
}
#endif /* HITLS_CRYPTO_ECDH */
