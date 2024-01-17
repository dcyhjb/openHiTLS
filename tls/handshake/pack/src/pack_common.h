/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef PACK_COMMON_H
#define PACK_COMMON_H

#include <stdint.h>
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Pack session ID
 *
 * @param   id [IN] Session ID
 * @param   idSize [IN] Session ID length
 * @param   buf [OUT] Message buffer
 * @param   bufLen [IN] Maximum message length
 * @param   usedLen [OUT] Length of message
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PACK_SESSIONID_ERR Failed to pack sessionId
 * @retval  HITLS_MEMCPY_FAIL Memory Copy Failed
 */
int32_t PackSessionId(const uint8_t *id, uint32_t idSize, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief   Pack DTLS message header
 *
 * @param   type [IN] Message type
 * @param   sequence [IN] Sequence number (only in DTLS)
 * @param   length [IN] Length of message body
 * @param   buf [OUT] Message header
 */
void PackDtlsMsgHeader(HS_MsgType type, uint16_t sequence, uint32_t length, uint8_t *buf);

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end PACK_COMMON_H */