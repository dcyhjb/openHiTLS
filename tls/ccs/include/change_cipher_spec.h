/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef CHANGE_CIPHER_SPEC_H
#define CHANGE_CIPHER_SPEC_H

#include <stdint.h>
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup change cipher spec
 * @brief CCS initialization function
 *
 * @param ctx [IN] SSL context
 *
 * @retval HITLS_SUCCESS                Initializition successful.
 * @retval HITLS_INTERNAL_EXCEPTION     An unexpected internal error occurs.
 * @retval HITLS_MEMALLOC_FAIL          Failed to apply for memory.
 */
int32_t CCS_Init(TLS_Ctx *ctx);

/**
 * @ingroup change cipher spec
 * @brief   CCS deinitialization function
 *
 * @param   ctx [IN] ssl context
 *
 */
void CCS_DeInit(TLS_Ctx *ctx);

/**
 * @ingroup change cipher spec
 * @brief   Check whether the Change cipher spec message is received.
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  True if the Change cipher spec message is received else false.
 */
bool CCS_IsRecv(const TLS_Ctx *ctx);

/**
 * @ingroup change cipher spec
 * @brief CCS packet received
 *
 * @param ctx [IN] TLS context
 * @param buf [IN] CCS message body
 * @param len [IN] CCS message length
 *
 */
void CCS_Recv(TLS_Ctx *ctx, const uint8_t *buf, uint32_t len);

/**
 * @ingroup change cipher spec
 * @brief Send a packet for changing the cipher suite.
 *
 * @param ctx [IN] TLS context
 *
 * @retval HITLS_SUCCESS                Send successful.
 * @retval HITLS_INTERNAL_EXCEPTION     An unexpected internal error occurs.
 * @retval For other error codes, see REC_Write.
 */
int32_t CCS_Send(TLS_Ctx *ctx);

/**
 * @ingroup change cipher spec
 * @brief Control function
 *
 * @param ctx [IN] TLS context
 * @param cmd [IN] Control command
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_INTERNAL_EXCEPTION     An unexpected internal error
 * @retval HITLS_CCS_INVALID_CMD        Invalid instruction
 */
int32_t CCS_Ctrl(TLS_Ctx *ctx, CCS_Cmd cmd);

#ifdef __cplusplus
}
#endif

#endif
