/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdbool.h>
#include "hitls_error.h"
#include "bsl_err_internal.h"
#include "hitls_type.h"
#include "rec.h"
#include "hs.h"
#include "app.h"
#include "alert.h"
#include "change_cipher_spec.h"
#include "conn_common.h"

// an instance of unexpectedMsgProcessCb
int32_t ConnUnexpectedMsg(HITLS_Ctx *ctx, uint32_t msgType, const uint8_t *data, uint32_t dataLen)
{
    if (ctx == NULL || data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    int32_t ret = HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    CM_State linkState = ctx->state;

    /* In closed state, only unexpected alert messages are received. */
    if (GetConnState(ctx) == CM_STATE_CLOSED) {
        if (msgType == REC_TYPE_ALERT) {
            ALERT_Recv(ctx, data, dataLen);
        }
        BSL_ERR_PUSH_ERROR(HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }

    switch (msgType) {
        case REC_TYPE_CHANGE_CIPHER_SPEC:
            CCS_Recv(ctx, data, dataLen);
            break;
        case REC_TYPE_ALERT:
            ALERT_Recv(ctx, data, dataLen);
            break;
        case REC_TYPE_HANDSHAKE:
            ret = HS_RecvUnexpectedMsgProcess(ctx, data, dataLen, &linkState);
            ChangeConnState(ctx, linkState);
            if (ret == HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE) {
                return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
            }
            break;
        case REC_TYPE_APP:
            if (HS_IsAppDataAllowed(ctx)) {
                APP_RecvUnexpectedMsgProcess(ctx, data, dataLen);
                break;
            }
            /* If app messages are not allowed to be received, needs send an alert message */
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
            break;
        default:
            ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
            break;
    }
    if (ret == HITLS_SUCCESS) {
        ret = HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }
    return ret;
}

int32_t CONN_Init(TLS_Ctx *ctx)
{
    int32_t ret;

    ret = REC_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = ALERT_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = CCS_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HS_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = APP_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ctx->method.isRecvCCS = CCS_IsRecv;
    ctx->method.sendCCS = CCS_Send;
    ctx->method.ctrlCCS = CCS_Ctrl;
    ctx->method.sendAlert = ALERT_Send;
    ctx->method.getAlertFlag = ALERT_GetFlag;
    ctx->method.unexpectedMsgProcessCb = ConnUnexpectedMsg;

    ctx->keyUpdateType = HITLS_KEY_UPDATE_REQ_END;
    ctx->isKeyUpdateRequest = false;

    // default value is X509_V_OK(0)
    ctx->peerInfo.verifyResult = 0;

    ctx->rwstate = HITLS_NOTHING;

    return HITLS_SUCCESS;
}

void CONN_Deinit(TLS_Ctx *ctx)
{
    REC_DeInit(ctx);
    ALERT_Deinit(ctx);
    CCS_DeInit(ctx);
    HS_DeInit(ctx);
    APP_DeInit(ctx);
    return;
}