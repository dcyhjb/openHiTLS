/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#include "securec.h"
#include "bsl_module_list.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "rec.h"
#include "rec_unprocessed_msg.h"


#ifndef HITLS_NO_DTLS12

void CacheNextEpochHsMsg(UnprocessedHsMsg *unprocessedHsMsg, const RecHdr *hdr, const uint8_t *recordBody)
{
    /* only out-of-order finished messages need to be cached */
    if (hdr->type != REC_TYPE_HANDSHAKE) {
        return;
    }

    /* only cache one */
    if (unprocessedHsMsg->recordBody != NULL) {
        return;
    }

    unprocessedHsMsg->recordBody = (uint8_t *)BSL_SAL_Dump(recordBody, hdr->bodyLen);
    if (unprocessedHsMsg->recordBody == NULL) {
        return;
    }

    (void)memcpy_s(&unprocessedHsMsg->hdr, sizeof(RecHdr), hdr, sizeof(RecHdr));
    return;
}

UnprocessedAppMsg *UnprocessedAppMsgNew(void)
{
    UnprocessedAppMsg *msg = (UnprocessedAppMsg *)BSL_SAL_Calloc(1, sizeof(UnprocessedAppMsg));
    if (msg == NULL) {
        return NULL;
    }

    LIST_INIT(&msg->head);
    return msg;
}

void UnprocessedAppMsgFree(UnprocessedAppMsg *msg)
{
    if (msg != NULL) {
        BSL_SAL_FREE(msg->recordBody);
        BSL_SAL_FREE(msg);
    }
    return;
}

void UnprocessedAppMsgListInit(UnprocessedAppMsg *appMsgList)
{
    if (appMsgList == NULL) {
        return;
    }
    appMsgList->count = 0;
    appMsgList->recordBody = NULL;
    LIST_INIT(&appMsgList->head);
    return;
}

void UnprocessedAppMsgListDeinit(UnprocessedAppMsg *appMsgList)
{
    ListHead *node = NULL;
    ListHead *tmpNode = NULL;
    UnprocessedAppMsg *cur = NULL;

    LIST_FOR_EACH_ITEM_SAFE(node, tmpNode, &(appMsgList->head)) {
        cur = LIST_ENTRY(node, UnprocessedAppMsg, head);
        LIST_REMOVE(node);
        /* releasing nodes and deleting user data */
        UnprocessedAppMsgFree(cur);
    }
    appMsgList->count = 0;
    return;
}

int32_t UnprocessedAppMsgListAppend(UnprocessedAppMsg *appMsgList, const RecHdr *hdr, const uint8_t *recordBody)
{
    /* prevent oversize */
    if (appMsgList->count >= UNPROCESSED_APP_MSG_COUNT_MAX) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_BUFFER_NOT_ENOUGH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15804, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Buffer app record: count[%u] is too big", appMsgList->count, 0, 0, 0);
        return HITLS_REC_ERR_BUFFER_NOT_ENOUGH;
    }

    UnprocessedAppMsg *appNode = UnprocessedAppMsgNew();
    if (appNode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15805, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Buffer app record: Malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    appNode->recordBody = (uint8_t*)BSL_SAL_Dump(recordBody, hdr->bodyLen);
    if (appNode->recordBody == NULL) {
        UnprocessedAppMsgFree(appNode);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15806, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Buffer app record: Malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(&appNode->hdr, sizeof(RecHdr), hdr, sizeof(RecHdr));

    LIST_ADD_BEFORE(&appMsgList->head, &appNode->head);

    appMsgList->count++;
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15807, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
        "Buffer app record: count is %u.", appMsgList->count, 0, 0, 0);
    return HITLS_SUCCESS;
}

UnprocessedAppMsg *UnprocessedAppMsgGet(UnprocessedAppMsg *appMsgList)
{
    ListHead *next = appMsgList->head.next;
    if (next == &appMsgList->head) {
        return NULL;
    }

    UnprocessedAppMsg *cur = LIST_ENTRY(next, UnprocessedAppMsg, head);
    /* remove a node and release it by the outside */
    LIST_REMOVE(next);
    appMsgList->count--;
    return cur;
}

#endif // HITLS_NO_DTLS12
