/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#include <stdint.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_log.h"
#include "bsl_bytes.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "hs_common.h"
#include "hitls_error.h"
#include "tls_binlog_id.h"


// The client processes the certificate request
int32_t ClientRecvCertRequestProcess(TLS_Ctx *ctx, HS_Msg *msg)
{
    /**
     *  If the server certificate is not received, a failure message is returned after the cert request is received
     *  RFC 5246 7.4.4: Note: It is a fatal handshake_failure alert for
     *  an anonymous server to request client authentication.
     */
    if (ctx->hsCtx->peerCert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15869, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "got cert request but not get peer certificate.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE;
    }
    /* If ECC and ECHDE of TLCP are used, this parameter must be set because the
     * TLCP server must send the req cert message to the client to send the certificate, which may be
     * used for identity authentication, The latter may be used for key derivation, depending on the cipher suite and
     * server configuration (isSupportClientVerify). */
    ctx->hsCtx->isNeedClientCert = true;

    CertificateRequestMsg *certReq = &msg->body.certificateReq;
    CERT_ExpectInfo expectCertInfo = {0};
    expectCertInfo.certType = CERT_TYPE_UNKNOWN;
    expectCertInfo.signSchemeList = certReq->signatureAlgorithms;
    expectCertInfo.signSchemeNum = certReq->signatureAlgorithmsSize;
    (void)SAL_CERT_SelectCertByInfo(ctx, &expectCertInfo);

    return HS_ChangeState(ctx, TRY_RECV_SERVER_HELLO_DONE);
}

int32_t Tls13ClientRecvCertRequestProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    const CertificateRequestMsg *certReq = &msg->body.certificateReq;

    /** If authentication is not performed after handshake, the cert req ctx length should be 0 */
    if ((ctx->phaState != PHA_REQUESTED && certReq->certificateReqCtxSize != 0) ||
        (ctx->phaState == PHA_REQUESTED && certReq->certificateReqCtxSize == 0)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15870, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "certificateReqCtxSize is invalid.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_MSG_HANDLE_INVALID_CERT_REQ_CTX;
    }
    if (certReq->certificateReqCtxSize != 0) {
        BSL_SAL_FREE(ctx->certificateReqCtx);
        ctx->certificateReqCtx = BSL_SAL_Calloc(certReq->certificateReqCtxSize, sizeof(uint8_t));
        if (ctx->certificateReqCtx == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        ctx->certificateReqCtxSize = certReq->certificateReqCtxSize;
        int32_t ret = memcpy_s(ctx->certificateReqCtx, certReq->certificateReqCtxSize,
            certReq->certificateReqCtx, certReq->certificateReqCtxSize);
        if (ret != EOK) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15406, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
                "client calloc cert req ctx failed.", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            return HITLS_MEMCPY_FAIL;
        }
    }

    ctx->hsCtx->isNeedClientCert = true;

    CERT_ExpectInfo expectCertInfo = {0};
    expectCertInfo.certType = CERT_TYPE_UNKNOWN;
    expectCertInfo.signSchemeList = certReq->signatureAlgorithms;
    expectCertInfo.signSchemeNum = certReq->signatureAlgorithmsSize;

    /* If no certificate is selected, the client sends an empty certificate message */
    (void)SAL_CERT_SelectCertByInfo(ctx, &expectCertInfo);
    if (ctx->phaState == PHA_REQUESTED) {
        return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE);
    }

    return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE);
}
