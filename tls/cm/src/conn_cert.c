/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#include <stddef.h>
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls_cert_type.h"
#include "hitls_cert.h"
#include "tls.h"

int32_t HITLS_SetVerifyStore(HITLS_Ctx *ctx, HITLS_CERT_Store *store, bool isClone)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetVerifyStore(&(ctx->config.tlsConfig), store, isClone);
}

HITLS_CERT_Store *HITLS_GetVerifyStore(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetVerifyStore(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetChainStore(HITLS_Ctx *ctx, HITLS_CERT_Store *store, bool isClone)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetChainStore(&(ctx->config.tlsConfig), store, isClone);
}

HITLS_CERT_Store *HITLS_GetChainStore(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetChainStore(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetCertStore(HITLS_Ctx *ctx, HITLS_CERT_Store *store, bool isClone)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetCertStore(&(ctx->config.tlsConfig), store, isClone);
}

HITLS_CERT_Store *HITLS_GetCertStore(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetCertStore(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetVerifyDepth(HITLS_Ctx *ctx, uint32_t depth)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetVerifyDepth(&(ctx->config.tlsConfig), depth);
}

int32_t HITLS_GetVerifyDepth(const HITLS_Ctx *ctx, uint32_t *depth)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetVerifyDepth(&(ctx->config.tlsConfig), depth);
}

int32_t HITLS_SetDefaultPasswordCb(HITLS_Ctx *ctx, HITLS_PasswordCb cb)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    int32_t ret = HITLS_CFG_SetDefaultPasswordCb(&(ctx->config.tlsConfig), cb);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}

HITLS_PasswordCb HITLS_GetDefaultPasswordCb(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetDefaultPasswordCb(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetDefaultPasswordCbUserdata(HITLS_Ctx *ctx, void *userdata)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    int32_t ret = HITLS_CFG_SetDefaultPasswordCbUserdata(&(ctx->config.tlsConfig), userdata);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}

void *HITLS_GetDefaultPasswordCbUserdata(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetDefaultPasswordCbUserdata(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetCertificate(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, bool isClone)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetCertificate(&(ctx->config.tlsConfig), cert, isClone);
}

int32_t HITLS_LoadCertFile(HITLS_Ctx *ctx, const char *file, HITLS_ParseFormat format)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_LoadCertFile(&(ctx->config.tlsConfig), file, format);
}

int32_t HITLS_LoadCertBuffer(HITLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_LoadCertBuffer(&(ctx->config.tlsConfig), buf, bufLen, format);
}

HITLS_CERT_X509 *HITLS_GetCertificate(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetCertificate(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetPrivateKey(HITLS_Ctx *ctx, HITLS_CERT_Key *key, bool isClone)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetPrivateKey(&(ctx->config.tlsConfig), key, isClone);
}

int32_t HITLS_LoadKeyFile(HITLS_Ctx *ctx, const char *file, HITLS_ParseFormat format)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_LoadKeyFile(&(ctx->config.tlsConfig), file, format);
}

int32_t HITLS_LoadKeyBuffer(HITLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_LoadKeyBuffer(&(ctx->config.tlsConfig), buf, bufLen, format);
}

HITLS_CERT_Key *HITLS_GetPrivateKey(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetPrivateKey(&(ctx->config.tlsConfig));
}

int32_t HITLS_CheckPrivateKey(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_CheckPrivateKey(&(ctx->config.tlsConfig));
}

int32_t HITLS_RemoveCertAndKey(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_RemoveCertAndKey(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetVerifyCb(HITLS_Ctx *ctx, HITLS_VerifyCb callback)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetVerifyCb(&(ctx->config.tlsConfig), callback);
}

HITLS_VerifyCb HITLS_GetVerifyCb(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetVerifyCb(&(ctx->config.tlsConfig));
}