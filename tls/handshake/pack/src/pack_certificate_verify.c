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
#include "tls.h"
#include "hs_ctx.h"

int32_t PackCertificateVerify(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = 0;
    uint32_t offset = 0u;
    const HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    if (hsCtx->verifyCtx->verifyDataSize == 0u) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15824, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the verify data is illegal.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (bufLen < sizeof(uint16_t) + sizeof(uint16_t) + hsCtx->verifyCtx->verifyDataSize) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15825, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the buffer length of certificate verify message is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }

    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLCP11) {
        BSL_Uint16ToByte((uint16_t)ctx->negotiatedInfo.signScheme, &buf[offset]);
        offset += sizeof(uint16_t);
    }

    /* Verify the data is the signature data. The maximum length of the signature data is 1024 bytes */
    BSL_Uint16ToByte((uint16_t)hsCtx->verifyCtx->verifyDataSize, &buf[offset]);
    offset += sizeof(uint16_t);

    ret = memcpy_s(&buf[offset], bufLen - offset, hsCtx->verifyCtx->verifyData, hsCtx->verifyCtx->verifyDataSize);
    if (ret != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15826, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "memcpy verify data fail when pack certificate verify msg.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    offset += hsCtx->verifyCtx->verifyDataSize;

    *usedLen = offset;
    return HITLS_SUCCESS;
}
