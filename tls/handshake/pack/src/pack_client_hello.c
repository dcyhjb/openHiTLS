/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdint.h>
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hitls_security.h"
#include "tls.h"
#include "security.h"
#include "cipher_suite.h"
#include "hs_ctx.h"
#include "pack_common.h"
#include "pack_extensions.h"


#define SINGLE_CIPHER_SUITE_SIZE 2u
#define CIPHER_SUITES_LEN_SIZE   2u

// Pack the version content of the client Hello message.
static int32_t PackClientVersion(const TLS_Ctx *ctx, uint16_t version, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    (void)bufLen;
    const TLS_Config *tlsConfig = &ctx->config.tlsConfig;
    uint32_t offset = 0u;

    int32_t ret = SECURITY_CfgCheck((HITLS_Config *)tlsConfig, HITLS_SECURITY_SECOP_VERSION, 0, version, NULL);
    if (ret != SECURITY_SUCCESS) {
        ctx->method.sendAlert((TLS_Ctx *)ctx, ALERT_LEVEL_FATAL, ALERT_INSUFFICIENT_SECURITY);
        BSL_ERR_PUSH_ERROR(HITLS_PACK_UNSECURE_VERSION);
        return HITLS_PACK_UNSECURE_VERSION;
    }
    BSL_Uint16ToByte(version, &buf[offset]);
    offset += sizeof(uint16_t);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

#ifndef HITLS_NO_DTLS12
// Pack the cookie content of the client Hello message.
static int32_t PackClientCookie(const uint8_t *cookie, uint8_t cookieLen,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0u;

    if (bufLen < (sizeof(uint8_t) + cookieLen)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_COOKIE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15730, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the buffer length of cookie is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_COOKIE_ERR;
    }

    buf[offset] = cookieLen;
    offset += sizeof(uint8_t);
    if (cookieLen == 0u) {
        *usedLen = offset;
        return HITLS_SUCCESS;
    }

    int32_t ret = memcpy_s(&buf[offset], bufLen - offset, cookie, cookieLen);
    if (ret != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15731, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "memcpy fail when pack cookie.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    offset += cookieLen;

    *usedLen = offset;
    return HITLS_SUCCESS;
}
#endif

static int32_t PackCipherSuites(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *offset, bool isTls13)
{
    uint16_t *cipherSuites = NULL;
    uint32_t cipherSuitesSize = 0;
    uint32_t tmpOffset = *offset;
    uint16_t minVersion = ctx->config.tlsConfig.minVersion;
    uint16_t maxVersion = ctx->config.tlsConfig.maxVersion;
    if (isTls13) {
        cipherSuites = ctx->config.tlsConfig.tls13CipherSuites;
        cipherSuitesSize = ctx->config.tlsConfig.tls13cipherSuitesSize;
    } else {
        cipherSuites = ctx->config.tlsConfig.cipherSuites;
        cipherSuitesSize = ctx->config.tlsConfig.cipherSuitesSize;
    }

    for (uint32_t i = 0; i < cipherSuitesSize; i++) {
        if ((CFG_CheckCipherSuiteSupported(cipherSuites[i]) != true) ||
		    (CFG_CheckCipherSuiteVersion(cipherSuites[i], minVersion, maxVersion) != true)) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15845, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
                "The cipher suite [0x%04x] is NOT supported, index=[%u].", cipherSuites[i], i, 0, 0);
            continue;
        }
        if (tmpOffset + sizeof(uint16_t) > bufLen) {
            BSL_ERR_PUSH_ERROR(HITLS_PACK_CLIENT_CIPHER_SUITE_ERR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15776, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack cipher suite error, the buffer length is not enough.", 0, 0, 0, 0);
            return HITLS_PACK_CLIENT_CIPHER_SUITE_ERR;
        }
        BSL_Uint16ToByte(cipherSuites[i], &buf[tmpOffset]);
        tmpOffset += sizeof(uint16_t);
    }

    *offset = tmpOffset;
    return HITLS_SUCCESS;
}

// Pack the cipher suites content of the client hello message.
static int32_t PackClientCipherSuites(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint16_t cipherSuitesLen = 0u;
    /* Finally fill in the length of the cipher suites */
    uint32_t offset = CIPHER_SUITES_LEN_SIZE;
    /* If the local is not in the renegotiation state,
     * you need to pack the SCSV algorithm set */
    bool isPackScsv = (!ctx->negotiatedInfo.isRenegotiation);
    if (ctx->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13) {
        ret = PackCipherSuites(ctx, buf, bufLen, &offset, 1);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    ret = PackCipherSuites(ctx, buf, bufLen, &offset, 0);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (offset == SINGLE_CIPHER_SUITE_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_CLIENT_CIPHER_SUITE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15732, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack cipher suite error, no cipher suite.", 0, 0, 0, 0);
        return HITLS_PACK_CLIENT_CIPHER_SUITE_ERR;
    }

    /* The cipher suite has been filled. Each cipher suite takes two bytes, so the length of the filled cipher suite can
     * be calculated according to offset */
    cipherSuitesLen = (uint16_t)(offset - CIPHER_SUITES_LEN_SIZE);
    if (isPackScsv) {
        cipherSuitesLen += sizeof(uint16_t);
        BSL_Uint16ToByte(TLS_EMPTY_RENEGOTIATION_INFO_SCSV, &buf[offset]);
        offset += sizeof(uint16_t);
    }
    if (offset > bufLen) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_CLIENT_CIPHER_SUITE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15733, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack cipher suite error, the buffer length is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_CLIENT_CIPHER_SUITE_ERR;
    }
    BSL_Uint16ToByte(cipherSuitesLen, &buf[0]);
    *usedLen = offset;
    return HITLS_SUCCESS;
}

// Pack the content of the method for compressing the client Hello message.
static int32_t PackClientCompressionMethod(uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0u;

    if (bufLen < sizeof(uint8_t) + sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_CLIENT_CIPHER_SUITE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15734, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack compression method error, the buffer length is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_CLIENT_CIPHER_SUITE_ERR;
    }

    buf[offset] = 1;
    offset += sizeof(uint8_t);
    buf[offset] = 0;           /* Compression methods Currently support uncompressed */
    offset += sizeof(uint8_t);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

// Pack the session and cookie content of the client hello message.
static int32_t PackSessionAndCookie(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    uint32_t len = 0;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    len = 0u;
    ret = PackSessionId(hsCtx->sessionId, hsCtx->sessionIdSize, &buf[offset], bufLen - offset, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += len;

#ifndef HITLS_NO_DTLS12
    const TLS_Config *tlsConfig = &ctx->config.tlsConfig;
    uint16_t version = (tlsConfig->maxVersion == HITLS_VERSION_TLS13) ? HITLS_VERSION_TLS12 : tlsConfig->maxVersion;
    if (IS_DTLS_VERSION(version)) {
        len = 0u;
        ret = PackClientCookie(ctx->negotiatedInfo.cookie, (uint8_t)ctx->negotiatedInfo.cookieSize,
            &buf[offset], bufLen - offset, &len);
        if (ret != HITLS_SUCCESS) {
            (void)memset_s(ctx->negotiatedInfo.cookie, ctx->negotiatedInfo.cookieSize,
                           0, ctx->negotiatedInfo.cookieSize);
            return ret;
        }
        offset += len;
    }
#endif

    *usedLen = offset;
    return HITLS_SUCCESS;
}

// Pack the mandatory content of the ClientHello message.
static int32_t PackClientHelloMandatoryField(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    /* The bufLen must be able to assemble at least the version number (2 bytes),
       random number (32 bytes), and session ID (1 byte) */
    if (bufLen < (sizeof(uint16_t) + HS_RANDOM_SIZE + sizeof(uint8_t))) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15126, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack client hello mandatory field error, the bufLen(%u) is not enough.", bufLen, NULL, NULL, NULL);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }
    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    uint32_t len = 0u;
    const TLS_Config *tlsConfig = &ctx->config.tlsConfig;
    if (ctx->hsCtx->clientRandom == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    uint16_t version = (tlsConfig->maxVersion == HITLS_VERSION_TLS13) ? HITLS_VERSION_TLS12 : tlsConfig->maxVersion;
    ret = PackClientVersion(ctx, version, buf, bufLen, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += len;

    (void)memcpy_s(&buf[offset], bufLen - offset, ctx->hsCtx->clientRandom, HS_RANDOM_SIZE);
    offset += HS_RANDOM_SIZE;

    len = 0u;
    ret = PackSessionAndCookie(ctx, &buf[offset], bufLen - offset, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += len;

    len = 0u;
    ret = PackClientCipherSuites(ctx, &buf[offset], bufLen - offset, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += len;

    len = 0u;
    ret = PackClientCompressionMethod(&buf[offset], bufLen - offset, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += len;

    *usedLen = offset;
    return HITLS_SUCCESS;
}

// Pack the ClientHello message to form the Handshake body.
int32_t PackClientHello(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    uint32_t msgLen = 0u;
    uint32_t exMsgLen = 0u;

    ret = PackClientHelloMandatoryField(ctx, buf, bufLen, &msgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15735, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack client hello mandatory content fail.", 0, 0, 0, 0);
        return ret;
    }
    offset += msgLen;
    exMsgLen = 0u;
    ret = PackClientExtension(ctx, &buf[offset], bufLen - offset, &exMsgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15736, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack client hello extension content fail.", 0, 0, 0, 0);
        return ret;
    }
    offset += exMsgLen;

    *usedLen = offset;
    return HITLS_SUCCESS;
}
