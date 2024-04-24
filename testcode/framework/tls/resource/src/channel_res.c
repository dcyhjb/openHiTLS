/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <sys/time.h>
#include "logger.h"
#include "securec.h"
#include "lock.h"
#include "channel_res.h"

#define SUCCESS 0
#define ERROR (-1)

static ControlChannelRes g_channelRes;

static int SetControlChannelRes(ControlChannelRes *channelInfo, char *srcDomainPath, char *peerDomainPath)
{
    int ret;

    // Translate the source address.
    ret = memset_s(&(channelInfo->srcAddr), sizeof(struct sockaddr_un), 0, sizeof(struct sockaddr_un));
    if (ret != EOK) {
        LOG_ERROR("memset_s Error\n");
        return ERROR;
    }

    ret = memcpy_s(channelInfo->srcDomainPath, DOMAIN_PATH_LEN, srcDomainPath, strlen(srcDomainPath));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s Error\n");
        return ERROR;
    }

    channelInfo->srcAddr.sun_family = AF_UNIX;
    ret = strcpy_s(channelInfo->srcAddr.sun_path, strlen(srcDomainPath) + 1, srcDomainPath);
    if (ret != EOK) {
        LOG_ERROR("strcpy_s Error");
        return ERROR;
    }

    ret = memset_s(channelInfo->peerDomainPath, sizeof(channelInfo->peerDomainPath),
                   0, sizeof(channelInfo->peerDomainPath));
    if (ret != EOK) {
        LOG_ERROR("memset_s Error\n");
        return ERROR;
    }

    if (peerDomainPath != NULL) {
        ret = memcpy_s(channelInfo->peerDomainPath, DOMAIN_PATH_LEN, peerDomainPath, strlen(peerDomainPath));
        if (ret != EOK) {
            LOG_ERROR("memcpy_s Error\n");
            return ERROR;
        }

        channelInfo->peerAddr.sun_family = AF_UNIX;
        ret = strcpy_s(channelInfo->peerAddr.sun_path, strlen(peerDomainPath) + 1, peerDomainPath);
        if (ret != EOK) {
            LOG_ERROR("strcpy_s Error");
            return ERROR;
        }
    }
    return SUCCESS;
}

int InitControlChannelRes(char *srcDomainPath, int srcDomainPathLen, char *peerDomainPath, int peerDomainPathLen)
{
    int ret;
    if ((srcDomainPathLen <= 0) && (peerDomainPathLen <= 0)) {
        LOG_ERROR("srcDomainPathLen or peerDomainPathLen is 0");
        return ERROR;
    }
    ret = memset_s(&g_channelRes, sizeof(ControlChannelRes), 0, sizeof(ControlChannelRes));
    if (ret != EOK) {
        return ERROR;
    }

    // Initializing the Send Buffer Lock
    g_channelRes.sendBufferLock = OsLockNew();
    if (g_channelRes.sendBufferLock == NULL) {
        LOG_ERROR("OsLockNew Error");
        return ERROR;
    }

    // Initialize the receive buffer lock.
    g_channelRes.rcvBufferLock = OsLockNew();
    if (g_channelRes.rcvBufferLock == NULL) {
        LOG_ERROR("OsLockNew Error");
        return ERROR;
    }

    // Initializes the communication address used for UDP Domain Socket communication.
    ret = SetControlChannelRes(&g_channelRes, srcDomainPath, peerDomainPath);

    return ret;
}

ControlChannelRes *GetControlChannelRes()
{
    return &g_channelRes;
}

int PushResultToChannelSendBuffer(ControlChannelRes *channelInfo, uint8_t *result)
{
    int ret;
    OsLock(channelInfo->sendBufferLock);
    if (channelInfo->sendBufferNum == MAX_SEND_BUFFER_NUM) {
        LOG_ERROR("Channel Send Buffer Is Full, Please Try Again");
        OsUnLock(channelInfo->sendBufferLock);
        return 1; // The value 1 indicates that the current buffer is full and needs to be retried.
    }
    (void)memset_s(channelInfo->sendBuffer + channelInfo->sendBufferNum,
                   CONTROL_CHANNEL_MAX_MSG_LEN, 0, CONTROL_CHANNEL_MAX_MSG_LEN);
    ret = memcpy_s(channelInfo->sendBuffer + channelInfo->sendBufferNum,
                   CONTROL_CHANNEL_MAX_MSG_LEN, result, strlen(result));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s Error");
        OsUnLock(channelInfo->sendBufferLock);
        return ERROR;
    }
    channelInfo->sendBufferNum++;
    channelInfo->sendBufferNum %= MAX_SEND_BUFFER_NUM;
    OsUnLock(channelInfo->sendBufferLock);
    return SUCCESS;
}

int PushResultToChannelRcvBuffer(ControlChannelRes *channelInfo, uint8_t *result)
{
    int ret;
    OsLock(channelInfo->rcvBufferLock);
    if (channelInfo->rcvBufferNum == MAX_RCV_BUFFER_NUM) {
        LOG_ERROR("Channel Send Buffer Is Full, Please Try Again");
        OsUnLock(channelInfo->rcvBufferLock);
        return 1; // The value 1 indicates that the current buffer is full and needs to be retried.
    }
    (void)memset_s(channelInfo->rcvBuffer + channelInfo->rcvBufferNum,
                   CONTROL_CHANNEL_MAX_MSG_LEN, 0, CONTROL_CHANNEL_MAX_MSG_LEN);
    ret = memcpy_s(channelInfo->rcvBuffer + channelInfo->rcvBufferNum,
                   CONTROL_CHANNEL_MAX_MSG_LEN, result, strlen(result));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s Error");
        OsUnLock(channelInfo->rcvBufferLock);
        return ERROR;
    }
    channelInfo->rcvBufferNum++;
    channelInfo->rcvBufferNum %= MAX_RCV_BUFFER_NUM;
    OsUnLock(channelInfo->rcvBufferLock);
    return SUCCESS;
}

int PushResultToChannelIdBuffer(ControlChannelRes *channelInfo, uint8_t *result, int id)
{
    int ret;
    OsLock(channelInfo->rcvBufferLock);
    (void)memset_s(channelInfo->rcvBuffer + (id % MAX_RCV_BUFFER_NUM),
                   CONTROL_CHANNEL_MAX_MSG_LEN, 0, CONTROL_CHANNEL_MAX_MSG_LEN);
    ret = memcpy_s(channelInfo->rcvBuffer + (id % MAX_RCV_BUFFER_NUM),
                   CONTROL_CHANNEL_MAX_MSG_LEN, result, strlen(result));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s Error");
        OsUnLock(channelInfo->rcvBufferLock);
        return ERROR;
    }
    OsUnLock(channelInfo->rcvBufferLock);
    return SUCCESS;
}

void FreeControlChannelRes()
{
    if (g_channelRes.tid != 0) {
        g_channelRes.isExit = true;
        pthread_join(g_channelRes.tid, NULL);
    }
    OsLockDestroy(g_channelRes.sendBufferLock);
    OsLockDestroy(g_channelRes.rcvBufferLock);
    memset_s(&g_channelRes, sizeof(g_channelRes), 0, sizeof(g_channelRes));
    return;
}
