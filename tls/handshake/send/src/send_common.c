/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "tls.h"
#include "rec.h"
#include "transcript_hash.h"
#include "hs_ctx.h"
#include "hs.h"
#include "send_process.h"
#include "indicator.h"


static int32_t TlsSendHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    ret = REC_Write(ctx, REC_TYPE_HANDSHAKE, hsCtx->msgBuf, hsCtx->msgLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Add hash data */
    ret = VERIFY_Append(hsCtx->verifyCtx, hsCtx->msgBuf, hsCtx->msgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15795, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "verify append fail when send handshake msg.", 0, 0, 0, 0);
        return ret;
    }

    INDICATOR_MessageIndicate(1, HS_GetVersion(ctx), REC_TYPE_HANDSHAKE, hsCtx->msgBuf, hsCtx->msgLen,
                              ctx, ctx->config.tlsConfig.msgArg);

    hsCtx->msgLen = 0;
    return HITLS_SUCCESS;
}

#ifndef HITLS_NO_DTLS12
int32_t DtlsSendFragmentHsMsg(TLS_Ctx *ctx, uint32_t maxRecPayloadLen)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;
    uint8_t *data = (uint8_t *)BSL_SAL_Calloc(1u, maxRecPayloadLen);
    if (data == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    /* Copy the fragment header */
    if (memcpy_s(data, maxRecPayloadLen, hsCtx->msgBuf, DTLS_HS_MSG_HEADER_SIZE) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15796, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "send handshake msg to record fail.", 0, 0, 0, 0);
        BSL_SAL_FREE(data);
        return HITLS_MEMCPY_FAIL;
    }

    uint32_t fragmentOffset = 0;
    uint32_t fragmentLen = 0;
    /* Obtain the length of the handshake msg body */
    uint32_t packetLen = BSL_ByteToUint24(&hsCtx->msgBuf[DTLS_HS_MSGLEN_ADDR]);

    while (packetLen > 0) {
        /* Calculate the fragment length */
        fragmentLen = packetLen;
        if (packetLen > (maxRecPayloadLen - DTLS_HS_MSG_HEADER_SIZE)) {
            fragmentLen = maxRecPayloadLen - DTLS_HS_MSG_HEADER_SIZE;
        }

        BSL_Uint24ToByte(fragmentOffset, &data[DTLS_HS_FRAGMENT_OFFSET_ADDR]);
        BSL_Uint24ToByte(fragmentLen, &data[DTLS_HS_FRAGMENT_LEN_ADDR]);
        /* Write fragmented data */
        if (memcpy_s(&data[DTLS_HS_MSG_HEADER_SIZE], maxRecPayloadLen - DTLS_HS_MSG_HEADER_SIZE,
            &hsCtx->msgBuf[DTLS_HS_MSG_HEADER_SIZE + fragmentOffset], fragmentLen) != EOK) {
            BSL_SAL_FREE(data);
            return HITLS_MEMCPY_FAIL;
        }

        /* Send to the record layer */
        ret = REC_Write(ctx, REC_TYPE_HANDSHAKE, data, fragmentLen + DTLS_HS_MSG_HEADER_SIZE);
        if (ret != HITLS_SUCCESS) {
            BSL_SAL_FREE(data);
            return ret;
        }
        fragmentOffset += fragmentLen;
        packetLen -= fragmentLen;
    }

    BSL_SAL_FREE(data);
    return HITLS_SUCCESS;
}
#endif

#ifndef HITLS_NO_DTLS12
static int32_t DtlsSendHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    uint32_t maxRecPayloadLen = 0;
    ret = REC_GetMaxWriteSize(ctx, &maxRecPayloadLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* No sharding required */
    if (maxRecPayloadLen >= hsCtx->msgLen) {
        /* Send to the record layer */
        ret = REC_Write(ctx, REC_TYPE_HANDSHAKE, hsCtx->msgBuf, hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15797, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "send handshake msg to record fail.", 0, 0, 0, 0);
            return ret;
        }
    } else {
        ret = DtlsSendFragmentHsMsg(ctx, maxRecPayloadLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    /* Add hash data */
    ret = VERIFY_Append(hsCtx->verifyCtx, hsCtx->msgBuf, hsCtx->msgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15798, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "verify append fail when send handshake msg.", 0, 0, 0, 0);
        return ret;
    }

    INDICATOR_MessageIndicate(1, HS_GetVersion(ctx), REC_TYPE_HANDSHAKE, hsCtx->msgBuf, hsCtx->msgLen,
                              ctx, ctx->config.tlsConfig.msgArg);

    hsCtx->msgLen = 0;
    hsCtx->nextSendSeq++;

    return HITLS_SUCCESS;
}
#endif

int32_t HS_SendMsg(TLS_Ctx *ctx)
{
    uint32_t version = HS_GetVersion(ctx);
    switch (version) {
        case HITLS_VERSION_TLS12:
        case HITLS_VERSION_TLS13:
#ifndef HITLS_NO_TLCP11
        case HITLS_VERSION_TLCP11:
#endif
            return TlsSendHandShakeMsg(ctx);
#ifndef HITLS_NO_DTLS12
        case HITLS_VERSION_DTLS12:
            return DtlsSendHandShakeMsg(ctx);
#endif
        default:
            break;
    }

    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15799, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Send handshake msg of unsupported version.", 0, 0, 0, 0);
    return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
}
