/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "simulate_io.h"
#include "hitls_error.h"
#include "bsl_sal.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "securec.h"

#define FAKE_BSL_UIO_FD 666

FrameUioUserData *FRAME_IO_CreateUserData(void)
{
    FrameUioUserData *userData = BSL_SAL_Calloc(1u, sizeof(FrameUioUserData));
    if (userData == NULL) {
        return NULL;
    }
    return userData;
}

void FRAME_IO_FreeUserData(FrameUioUserData *userData)
{
    if (userData == NULL) {
        return;
    }

    BSL_SAL_FREE(userData);
    return;
}

int32_t FRAME_Write(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    *writeLen = 0;
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(uio);
    if (ioUserData == NULL) {
        return BSL_NULL_INPUT;
    }

    // This indicates that there is still a message in the buffer. The second message can be sent only after the peer
    // end receives the message.
    if (ioUserData->sndMsg.len != 0) {
        return BSL_SUCCESS;
    }

    memcpy_s(ioUserData->sndMsg.msg, MAX_RECORD_LENTH, buf, len);
    ioUserData->sndMsg.len = len;
    *writeLen = len;

    return BSL_SUCCESS;
}

int32_t FRAME_Read(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    *readLen = 0;
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(uio);
    if (ioUserData == NULL) {
        return BSL_NULL_INPUT;
    }
    // This indicates that the user inserts data. Therefore, the simulated data inserted by the user is received first.
    if (ioUserData->userInsertMsg.len != 0) {
        if (len < ioUserData->userInsertMsg.len) {
            return BSL_UIO_FAIL;
        }

        memcpy_s(buf, len, ioUserData->userInsertMsg.msg, ioUserData->userInsertMsg.len);
        *readLen = ioUserData->userInsertMsg.len;
        ioUserData->userInsertMsg.len = 0;
        return BSL_SUCCESS;
    } else if (ioUserData->recMsg.len != 0) {
        if (len < ioUserData->recMsg.len) {
            return BSL_UIO_FAIL;
        }

        memcpy_s(buf, len, ioUserData->recMsg.msg, ioUserData->recMsg.len);
        *readLen = ioUserData->recMsg.len;
        ioUserData->recMsg.len = 0;
        return BSL_SUCCESS;
    }  // If there is no data in the receive buffer, a success message is returned and *readLen is set to 0.

    return BSL_SUCCESS;
}

int32_t FRAME_Ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *param)
{
    (void)uio;
    (void)larg;
    if (cmd == BSL_UIO_SCTP_SND_BUFF_IS_EMPTY) {
        *(uint8_t *)param = true;
    }

    if (cmd == BSL_UIO_GET_FD) {
        *(int32_t *)param = FAKE_BSL_UIO_FD;
    }

    return BSL_SUCCESS;
}

/*
    Frame_TransportSendMsg: Sends messages in the send buffer in the I/O.
    Copy uio->userData to the buffer.
*/
int32_t FRAME_TransportSendMsg(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    *readLen = 0;
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(uio);
    if (ioUserData == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (ioUserData->sndMsg.len != 0) {
        // The length of the data in the buffer exceeds len.
        if (len < ioUserData->sndMsg.len) {
            return HITLS_UIO_FAIL;
        }

        memcpy_s(buf, len, ioUserData->sndMsg.msg, ioUserData->sndMsg.len);
        *readLen = ioUserData->sndMsg.len;
        ioUserData->sndMsg.len = 0;
    }  // If there is no data in the receive buffer, a success message is returned and *readLen is set to 0.

    return HITLS_SUCCESS;
}

/*
    Frame_TransportRecMsg simulates receiving messages from the I/O.
    Copy the data in the buffer to uio->userData.
*/
int32_t FRAME_TransportRecMsg(BSL_UIO *uio, void *buf, uint32_t len)
{
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(uio);
    if (ioUserData == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (ioUserData->recMsg.len != 0 || len > MAX_RECORD_LENTH) {
        return HITLS_UIO_FAIL;
    }

    memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, buf, len);
    ioUserData->recMsg.len = len;

    return HITLS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
