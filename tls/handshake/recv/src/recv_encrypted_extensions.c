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
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "hs_msg.h"
#include "hs_verify.h"


typedef int32_t (*CheckEncryptedExtFunc)(TLS_Ctx *ctx, const EncryptedExtensions *eEMsg);

static int32_t Tls13ClientCheckServerName(TLS_Ctx *ctx, const EncryptedExtensions *eEMsg)
{
    if ((ctx->hsCtx->extFlag.haveServerName == false) && (eEMsg->haveServerName == true)) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15337, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send server_name but get extended server_name .", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    /* Receive empty server_name extension */
    if ((ctx->hsCtx->extFlag.haveServerName == true) && (eEMsg->haveServerName == true)) {
        /* Not in session resumption and the client has previously sent the server_name extension */
        if (ctx->session == NULL && ctx->config.tlsConfig.serverName != NULL &&
            ctx->config.tlsConfig.serverNameSize > 0) {
            /* Indicates server negotiated the server_name extension in client successfully */
            ctx->negotiatedInfo.isSniStateOK = true;
            ctx->hsCtx->serverNameSize = ctx->config.tlsConfig.serverNameSize;

            ctx->hsCtx->serverName =
                (uint8_t *)BSL_SAL_Dump(ctx->config.tlsConfig.serverName, ctx->hsCtx->serverNameSize * sizeof(uint8_t));
            if (ctx->hsCtx->serverName == NULL) {
                return HITLS_MEMCPY_FAIL;
            }
        }
    }

    return HITLS_SUCCESS;
}

static int32_t ClientCheckEncryptedExtensionsFlag(TLS_Ctx *ctx, const EncryptedExtensions *eEMsg)
{
    static const CheckEncryptedExtFunc EXT_INFO_LIST[] = {
        Tls13ClientCheckServerName,
    };

    int32_t ret;
    for (uint32_t i = 0; i < sizeof(EXT_INFO_LIST) / sizeof(EXT_INFO_LIST[0]); i++) {
        ret = EXT_INFO_LIST[i](ctx, eEMsg);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_SUCCESS;
}

int32_t Tls13ClientRecvEncryptedExtensionsProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret;

    const EncryptedExtensions *eEMsg = &msg->body.encryptedExtensions;

    ret = ClientCheckEncryptedExtensionsFlag(ctx, eEMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* In psk_only mode, the next message is finish message, server verify data needs to be calculated. */
    PskInfo13 *pskInfo = &ctx->hsCtx->kxCtx->pskInfo13;
    if ((pskInfo->psk != NULL)) {
        ret = VERIFY_Tls13CalcVerifyData(ctx, false);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15856, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client calculate server finished data error.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return ret;
        }

        return HS_ChangeState(ctx, TRY_RECV_FINISH);
    }

    return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE_REQUEST);
}
