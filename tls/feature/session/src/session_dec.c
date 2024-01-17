/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdbool.h>
#include "securec.h"
#include "tlv.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "session_enc.h"
#include "session_type.h"

#define MAX_PSK_IDENTITY_LEN 0xffff
#define MAX_HOST_NAME_LEN 0xff

typedef int32_t (*PfuncDecSessionObjFunc)(HITLS_Session *sess, SessionObjType type, const uint8_t *data,
    uint32_t length, uint32_t *readLen);

typedef struct {
    SessionObjType type;
    PfuncDecSessionObjFunc func;
} SessObjDecFunc;

static int32_t DecSessObjVersion(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    int32_t ret;
    uint16_t version = 0;
    BSL_Tlv tlv = {0};
    tlv.length = sizeof(version);
    tlv.value = (uint8_t *)&version;

    ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_VERSION_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15993, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session obj version fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_VERSION_FAIL;
    }

    sess->version = version;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjCipherSuite(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    int32_t ret;
    uint16_t cipherSuite = 0;
    BSL_Tlv tlv = {0};
    tlv.length = sizeof(cipherSuite);
    tlv.value = (uint8_t *)&cipherSuite;

    ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_CIPHER_SUITE_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15994, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session obj cipher suite fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_CIPHER_SUITE_FAIL;
    }

    sess->cipherSuite = cipherSuite;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjMasterSecret(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    int32_t ret;
    BSL_Tlv tlv = {0};
    tlv.length = MAX_MASTER_KEY_SIZE;
    tlv.value = sess->masterKey;

    ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_MASTER_SECRET_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15995, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session obj master secret fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_MASTER_SECRET_FAIL;
    }

    sess->masterKeySize = tlv.length;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjPskIdentity(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    int32_t ret;
    uint32_t offset = sizeof(uint32_t);
    // The length has been verified at the upper layer and must be greater than 8 bytes.
    uint32_t tlvLen = BSL_ByteToUint32(&data[offset]);
    if (tlvLen > MAX_PSK_IDENTITY_LEN || tlvLen == 0) {
        return HITLS_SESS_ERR_DEC_PSK_IDENTITY_FAIL;
    }
    uint8_t *pskIdentity = BSL_SAL_Calloc(1u, tlvLen);
    if (pskIdentity == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15996, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "malloc pskIdentity fail when decode session obj psk identity.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    BSL_Tlv tlv = {0};
    tlv.length = tlvLen;
    tlv.value = pskIdentity;

    ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(pskIdentity);
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_PSK_IDENTITY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15997, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session obj psk identity fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_PSK_IDENTITY_FAIL;
    }

    sess->pskIdentity = tlv.value;
    sess->pskIdentitySize = tlv.length;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjStartTime(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    int32_t ret;
    uint64_t startTime = 0;
    BSL_Tlv tlv = {0};
    tlv.length = sizeof(startTime);
    tlv.value = (uint8_t *)&startTime;

    ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_START_TIME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15998, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session obj start time fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_START_TIME_FAIL;
    }

    sess->startTime = startTime;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjTimeout(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    int32_t ret;
    uint64_t timeout = 0;
    BSL_Tlv tlv = {0};
    tlv.length = sizeof(timeout);
    tlv.value = (uint8_t *)&timeout;

    ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_TIME_OUT_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15999, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session obj timeout fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_TIME_OUT_FAIL;
    }

    sess->timeout = timeout;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjHostName(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    int32_t ret;
    uint32_t offset = sizeof(uint32_t);
    // The length has been verified at the upper layer and must be greater than 8 bytes.
    uint32_t tlvLen = BSL_ByteToUint32(&data[offset]);
    if (tlvLen > MAX_HOST_NAME_LEN || tlvLen == 0) {
        return HITLS_SESS_ERR_DEC_HOST_NAME_FAIL;
    }
    uint8_t *hostName = BSL_SAL_Calloc(1u, tlvLen);
    if (hostName == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16000, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "malloc hostName fail when decode session obj host name.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    BSL_Tlv tlv = {0};
    tlv.length = tlvLen;
    tlv.value = hostName;

    ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(hostName);
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_HOST_NAME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16001, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session obj host name fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_HOST_NAME_FAIL;
    }

    sess->hostName = tlv.value;
    sess->hostNameSize = tlv.length;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjSessionIdCtx(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    int32_t ret;
    BSL_Tlv tlv = {0};
    tlv.length = HITLS_SESSION_ID_MAX_SIZE;
    tlv.value = sess->sessionIdCtx;

    ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_SESSION_ID_CTX_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16002, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session obj session id ctx fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_SESSION_ID_CTX_FAIL;
    }

    sess->sessionIdCtxSize = tlv.length;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjSessionId(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    int32_t ret;
    BSL_Tlv tlv = {0};
    tlv.length = HITLS_SESSION_ID_MAX_SIZE;
    tlv.value = sess->sessionId;

    ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_SESSION_ID_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16003, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session obj session id fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_SESSION_ID_FAIL;
    }

    sess->sessionIdSize = tlv.length;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjExtendMasterSecret(HITLS_Session *sess, SessionObjType type, const uint8_t *data,
    uint32_t length, uint32_t *readLen)
{
    int32_t ret;
    uint8_t haveExtMasterSecret = 0;
    BSL_Tlv tlv = {0};
    tlv.length = sizeof(haveExtMasterSecret);
    tlv.value = &haveExtMasterSecret;

    ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_EXT_MASTER_SECRET_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16004, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session obj extend master secret fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_EXT_MASTER_SECRET_FAIL;
    }

    sess->haveExtMasterSecret = (bool)haveExtMasterSecret;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjVerifyResult(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    int32_t ret;
    uint32_t verifyResult = 0;
    BSL_Tlv tlv = {0};
    tlv.length = sizeof(verifyResult);
    tlv.value = (uint8_t *)&verifyResult;

    ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_VERIFY_RESULT_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16005, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session obj verify result fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_VERIFY_RESULT_FAIL;
    }

    sess->verifyResult = (int32_t)verifyResult;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjTicketAgeAdd(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    int32_t ret;
    uint32_t ticketAgeAdd = 0;
    BSL_Tlv tlv = {0};
    tlv.length = sizeof(ticketAgeAdd);
    tlv.value = (uint8_t *)&ticketAgeAdd;

    ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_START_TIME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15975, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session obj TicketAgeAdd fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_START_TIME_FAIL;
    }

    sess->ticketAgeAdd = ticketAgeAdd;
    return HITLS_SUCCESS;
}

/**
 * Decoding function list.
 * Ensure that the sequence of decode and encode types is the same.
 */
static const SessObjDecFunc OBJ_LIST[] = {
    {SESS_OBJ_VERSION, DecSessObjVersion},
    {SESS_OBJ_CIPHER_SUITE, DecSessObjCipherSuite},
    {SESS_OBJ_MASTER_SECRET, DecSessObjMasterSecret},
    {SESS_OBJ_PSK_IDENTITY, DecSessObjPskIdentity},
    {SESS_OBJ_START_TIME, DecSessObjStartTime},
    {SESS_OBJ_TIMEOUT, DecSessObjTimeout},
    {SESS_OBJ_HOST_NAME, DecSessObjHostName},
    {SESS_OBJ_SESSION_ID_CTX, DecSessObjSessionIdCtx},
    {SESS_OBJ_SESSION_ID, DecSessObjSessionId},
    {SESS_OBJ_SUPPORT_EXTEND_MASTER_SECRET, DecSessObjExtendMasterSecret},
    {SESS_OBJ_VERIFY_RESULT, DecSessObjVerifyResult},
    {SESS_OBJ_AGE_ADD, DecSessObjTicketAgeAdd},
};

int32_t SESS_Decode(HITLS_Session *sess, const uint8_t *data, uint32_t length)
{
    if (sess == NULL || data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16006, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SESS_Decode input parameter is NULL.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    int32_t ret;
    uint32_t index;
    const uint8_t *curPos = data;
    uint32_t offset = 0;
    uint32_t readLen = 0;

    for (index = 0; index < sizeof(OBJ_LIST) / sizeof(SessObjDecFunc); index++) {
        if (length - offset < TLV_HEADER_LENGTH) {
            BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DECODE_TICKET);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16009, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "SESS_Decode length error, offset is %u, length is %u.", offset, length, 0, 0);
            return HITLS_SESS_ERR_DECODE_TICKET;
        }

        uint32_t type = BSL_ByteToUint32(curPos);
        if (OBJ_LIST[index].type != type) {
            continue;
        }
        readLen = 0;
        ret = OBJ_LIST[index].func(sess, OBJ_LIST[index].type, curPos, length - offset, &readLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        offset += readLen;
        curPos += readLen;
    }
    if (offset != length) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DECODE_TICKET);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16007, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SESS_Decode fail, offset is %u, length is %u.", offset, length, 0, 0);
        return HITLS_SESS_ERR_DECODE_TICKET;
    }

    return HITLS_SUCCESS;
}
