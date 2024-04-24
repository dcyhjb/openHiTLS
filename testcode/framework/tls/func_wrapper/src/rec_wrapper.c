/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "rec_wrapper.h"
#include "hs_ctx.h"
#define MAX_BUF 16384
static RecWrapper g_recWrapper;
static bool g_enableWrapper;
static __thread uint8_t g_locBuffer[MAX_BUF] = { 0 };

void RegisterWrapper(RecWrapper wrapper)
{
    g_enableWrapper = true;
    g_recWrapper = wrapper;
}

void ClearWrapper()
{
    g_enableWrapper = false;
}

extern int32_t __real_REC_Read(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num);

extern int32_t __real_REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num);

extern int32_t __wrap_REC_Read(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num)
{
    int32_t ret = __real_REC_Read(ctx, recordType, data, readLen, num);
    if (!g_enableWrapper || ret != 0 || !g_recWrapper.isRecRead || g_recWrapper.recordType != recordType) {
        return ret;
    }
    if (g_recWrapper.recordType == REC_TYPE_HANDSHAKE && ctx->hsCtx->state != g_recWrapper.ctrlState) {
        return ret;
    }
    g_recWrapper.func(ctx, data, readLen, num, g_recWrapper.userData);
    return ret;
}

extern int32_t __wrap_REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    // Length that can be manipulated in wrapper
    int manipulateLen = num;
    if (!g_enableWrapper || g_recWrapper.isRecRead || g_recWrapper.recordType != recordType) {
        return __real_REC_Write(ctx, recordType, data, manipulateLen);
    }
    if (g_recWrapper.recordType == REC_TYPE_HANDSHAKE && ctx->hsCtx->state != g_recWrapper.ctrlState) {
        return __real_REC_Write(ctx, recordType, data, manipulateLen);
    }
    (void)memcpy_s(g_locBuffer, MAX_BUF, data, num);
    // The value of manipulateLen can be greater than or smaller than num
    g_recWrapper.func(ctx, g_locBuffer, &manipulateLen, MAX_BUF, g_recWrapper.userData);
    if (ctx->hsCtx->bufferLen < manipulateLen) {
        exit(-1);
    }
    (void)memcpy_s(ctx->hsCtx->msgBuf, ctx->hsCtx->bufferLen, g_locBuffer, manipulateLen);
    ctx->hsCtx->msgLen = manipulateLen;
    return __real_REC_Write(ctx, recordType, g_locBuffer, manipulateLen);
}