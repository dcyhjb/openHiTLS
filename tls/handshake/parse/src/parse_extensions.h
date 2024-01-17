/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef PARSE_EXTENSIONS_H
#define PARSE_EXTENSIONS_H

#include <stdint.h>
#include "tls.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Parse Client Hello extension
 *
 * @attention The input parameter pointer can't be NULL
 *            If parsing fails, the invoker releases the allocated memory
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer, starting from the extension type
 * @param   bufLen [IN] Message length
 * @param   msg [OUT] Parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 * @retval  HITLS_PARSE_DUPLICATE_EXTENDED_MSG Extension duplicated
 */
int32_t ParseClientExtension(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg);

/**
 * @brief   Release the buffer in the Client Hello extension structure
 *
 * @param   msg [IN] Message structure
 */
void CleanClientHelloExtension(ClientHelloMsg *msg);

/**
 * @brief   Parse server hello extension
 *
 * @attention The input parameter pointer can't be NULL
 *            If the parsing fails, the invoker releases the allocated memory
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer, starting from the extension type
 * @param   bufLen [IN] Message length
 * @param   msg [OUT] Parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 * @retval  HITLS_PARSE_DUPLICATE_EXTENDED_MSG Extension duplicated
 * @retval  HITLS_PARSE_UNSUPPORTED_EXTENSION Unsupported extension
 */
int32_t ParseServerExtension(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg);
/**
 * @brief   Parse extension type and length
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer, starting from the extension type
 * @param   bufLen [IN] Message length
 * @param   extMsgType [OUT] Extension type
 * @param   extMsgLen [OUT] Extension length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 * @retval  HITLS_PARSE_DUPLICATE_EXTENDED_MSG Extension duplicated
 */
int32_t ParseExHeader(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint16_t *extMsgType, uint32_t *extMsgLen);
/**
 * @brief   Release the buffer in the Server Hello extension structure
 *
 * @param   msg [IN] Message structure
 */
void CleanServerHelloExtension(ServerHelloMsg *msg);
/**
 * @brief   Parse empty extension
 *
 * @param   ctx [IN] TLS context
 * @param   extMsgType [IN] Extension type
 * @param   extMsgLen [IN] Extension length
 * @param   haveExtension [OUT] Indicates whether there are extensions
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_PARSE_DUPLICATE_EXTENDED_MSG Extension duplicated
 */
int32_t ParseEmptyExtension(TLS_Ctx *ctx, uint16_t extMsgType, uint32_t extMsgLen, bool *haveExtension);

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end PARSE_EXTENSIONS_H */
