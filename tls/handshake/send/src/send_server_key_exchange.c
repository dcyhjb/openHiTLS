/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "hitls_crypt_type.h"
#include "hitls_security.h"
#include "tls.h"
#include "security.h"
#include "cert_method.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "pack.h"
#include "send_process.h"

#define DEFAULT_DHE_PSK_BIT_NUM 128
#define TLS_DHE_PARAM_MAX_LEN 1024

static HITLS_CRYPT_Key *GenerateDhEphemeralKey(HITLS_CRYPT_Key *priKey)
{
    uint8_t p[TLS_DHE_PARAM_MAX_LEN] = {0};
    uint8_t g[TLS_DHE_PARAM_MAX_LEN] = {0};
    uint16_t pLen = TLS_DHE_PARAM_MAX_LEN;
    uint16_t gLen = TLS_DHE_PARAM_MAX_LEN;

    int32_t ret = SAL_CRYPT_GetDhParameters(priKey, p, &pLen, g, &gLen);
    if (ret != HITLS_SUCCESS) {
        return NULL;
    }
    return SAL_CRYPT_GenerateDhKeyByParams(p, pLen, g, gLen);
}

static HITLS_CRYPT_Key *GetDhKey(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HITLS_Config *config = &ctx->config.tlsConfig;
    CERT_MgrCtx *certMgrCtx = config->certMgrCtx;
    HITLS_CRYPT_Key *key = NULL;
    int32_t secBits = 0;

    if (ctx->config.tlsConfig.isSupportDhAuto) {
        KeyExchCtx *keyExCtx = ctx->hsCtx->kxCtx;
        CipherSuiteInfo *cipherSuiteInfo = &ctx->negotiatedInfo.cipherSuiteInfo;
        HITLS_CERT_X509 *cert = SAL_CERT_GetCurrentCert(certMgrCtx);

        if ((keyExCtx->keyExchAlgo == HITLS_KEY_EXCH_DHE_PSK) ||
            ((keyExCtx->keyExchAlgo == HITLS_KEY_EXCH_DHE) && (cipherSuiteInfo->authAlg == HITLS_AUTH_NULL))) {
            secBits = (SECURITY_GetSecbits(ctx->config.tlsConfig.securityLevel) == 0)
                          ? DEFAULT_DHE_PSK_BIT_NUM
                          : SECURITY_GetSecbits(ctx->config.tlsConfig.securityLevel);
        } else if (cert != NULL) {
            HITLS_CERT_Key *pubkey = NULL;
            (void)SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
            ret = SAL_CERT_KeyCtrl(config, pubkey, CERT_KEY_CTRL_GET_SECBITS, NULL, (void *)&secBits);
            SAL_CERT_KeyFree(certMgrCtx, pubkey);
            if (ret != HITLS_SUCCESS) {
                return NULL;
            }
        }
        key = SAL_CRYPT_GenerateDhKeyBySecbits(secBits);
    } else {
        key = ctx->config.tlsConfig.dhTmp;
        if (key != NULL) {
            key = GenerateDhEphemeralKey(key);
        }
        /* Temporary DH security check */
        ret = SAL_CERT_KeyCtrl(config, key, CERT_KEY_CTRL_GET_SECBITS, NULL, (void *)&secBits);
        if (ret != HITLS_SUCCESS) {
            SAL_CRYPT_FreeDhKey(key);
            return NULL;
        }
        ret = SECURITY_SslCheck((HITLS_Ctx *)ctx, HITLS_SECURITY_SECOP_TMP_DH, secBits, 0, key);
        if (ret != SECURITY_SUCCESS) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INSUFFICIENT_SECURITY);
            SAL_CRYPT_FreeDhKey(key);
            return NULL;
        }
    }
    return key;
}

// Generate the DH cipher suite parameters
static int32_t GenDhCipherSuiteParams(TLS_Ctx *ctx)
{
    HITLS_CRYPT_Key *key = GetDhKey(ctx);
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ERR_GET_DH_KEY);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15744, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get dh key error when processing dh cipher suite.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_ERR_GET_DH_KEY;
    }

    uint8_t p[TLS_DHE_PARAM_MAX_LEN] = {0};
    uint8_t g[TLS_DHE_PARAM_MAX_LEN] = {0};
    uint16_t pLen = TLS_DHE_PARAM_MAX_LEN;
    uint16_t gLen = TLS_DHE_PARAM_MAX_LEN;

    /* Get p and g */
    if (SAL_CRYPT_GetDhParameters(key, p, &pLen, g, &gLen) != HITLS_SUCCESS) {
        SAL_CRYPT_FreeDhKey(key);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ERR_GET_DH_PARAMETERS);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15745, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get dh parameters error when processing dh cipher suite.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_ERR_GET_DH_PARAMETERS;
    }
    ctx->hsCtx->kxCtx->keyExchParam.dh.p = BSL_SAL_Dump(p, pLen);
    if (ctx->hsCtx->kxCtx->keyExchParam.dh.p == NULL) {
        SAL_CRYPT_FreeDhKey(key);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ERR_GET_DH_PARAMETERS);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15334, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get dh parameters error when processing dh cipher suite.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_ERR_GET_DH_PARAMETERS;
    }
    ctx->hsCtx->kxCtx->keyExchParam.dh.g = BSL_SAL_Dump(g, gLen);
    if (ctx->hsCtx->kxCtx->keyExchParam.dh.g == NULL) {
            BSL_SAL_FREE(ctx->hsCtx->kxCtx->keyExchParam.dh.p);
            SAL_CRYPT_FreeDhKey(key);
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ERR_GET_DH_PARAMETERS);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15333, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "get dh parameters error when processing dh cipher suite.", 0, 0, 0, 0);
            return HITLS_MSG_HANDLE_ERR_GET_DH_PARAMETERS;
    }
    ctx->hsCtx->kxCtx->keyExchParam.dh.plen = pLen;
    ctx->hsCtx->kxCtx->keyExchParam.dh.glen = gLen;
    ctx->hsCtx->kxCtx->key = key;
    return HITLS_SUCCESS;
}

static int32_t PackExchMsgPrepare(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HITLS_CRYPT_Key *key = NULL;

    switch (ctx->hsCtx->kxCtx->keyExchAlgo) {
        case HITLS_KEY_EXCH_ECDHE: /** TLCP is included here. */
        case HITLS_KEY_EXCH_ECDHE_PSK:
            key = SAL_CRYPT_GenEcdhKeyPair(&ctx->hsCtx->kxCtx->keyExchParam.ecdh.curveParams);
            if (key == NULL) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15746, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "server generate ecdhe key pair error.", 0, 0, 0, 0);
                return HITLS_CRYPT_ERR_ENCODE_ECDH_KEY;
            }
            ctx->hsCtx->kxCtx->key = key;
            break;
        case HITLS_KEY_EXCH_DHE:
        case HITLS_KEY_EXCH_DHE_PSK:
            ret = GenDhCipherSuiteParams(ctx);
            if (ret != HITLS_SUCCESS) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15747, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "server generate dh key params error.", 0, 0, 0, 0);
                return ret;
            }
            break;
        case HITLS_KEY_EXCH_PSK:
        case HITLS_KEY_EXCH_RSA_PSK:
#ifndef HITLS_NO_TLCP11
        case HITLS_KEY_EXCH_ECC:
#endif
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_KX_ALG);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15748, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "unsupport kx algorithm when send server kx msg.", 0, 0, 0, 0);
            return HITLS_MSG_HANDLE_UNSUPPORT_KX_ALG;
    }

    return HITLS_SUCCESS;
}

int32_t ServerSendServerKeyExchangeProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /** Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        ret = PackExchMsgPrepare(ctx);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15941, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Fail to PackExchMsgPrepare, ret = %d.", ret, 0, 0, 0);
            return ret;
        }

        ret = HS_PackMsg(ctx, SERVER_KEY_EXCHANGE, hsCtx->msgBuf, REC_MAX_PLAIN_LENGTH, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15749, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Fail to pack Server Key Exchange Message, HS_PackMsg ret = %d", ret, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15750, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send keyExchange msg success.", 0, 0, 0, 0);

    /** Update the state machine. If the CertificateRequest message does not need to be sent, the system directly
     * switches to theSend_SERVER_HELLO_DONE state */
    if (ctx->negotiatedInfo.cipherSuiteInfo.authAlg != HITLS_AUTH_NULL &&
        ctx->negotiatedInfo.cipherSuiteInfo.authAlg != HITLS_AUTH_PSK &&
        (ctx->config.tlsConfig.isSupportClientVerify == true) &&
        (SAL_CERT_GetCurrentCert(ctx->config.tlsConfig.certMgrCtx) != NULL)) {
        if (ctx->negotiatedInfo.certReqSendTime < 1 || !(ctx->config.tlsConfig.isSupportClientOnceVerify)) {
            return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE_REQUEST);
        }
    }
    /* Make sure the client will always send a certificate message, because ECDHE relies on the client's encrypted
     * certificate, even if the client does not require authentication (isSupportClientVerify equals false). */
#ifndef HITLS_NO_TLCP11
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP11 &&
        ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite == HITLS_ECDHE_SM4_CBC_SM3) {
        return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE_REQUEST);
    }
#endif
    return HS_ChangeState(ctx, TRY_SEND_SERVER_HELLO_DONE);
}