/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef HS_H
#define HS_H

#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Initialize the handshake context
 *
 * @param   ctx [IN] TLS object
 *
 * @retval  HITLS_SUCCESS succeeded
 */
int32_t HS_Init(TLS_Ctx *ctx);

/**
 * @brief   Release the handshake context
 *
 * @param   ctx [IN] TLS object
 */
void HS_DeInit(TLS_Ctx *ctx);

/**
 * @brief   Establish a TLS connection
 *
 * @param   ctx [IN] TLS object
 *
 * @retval  HITLS_SUCCESS The connection is successfully established.
 * @retval  For details about other error codes, see hitls_error.h
 */
int32_t HS_DoHandshake(TLS_Ctx *ctx);

/**
 * @brief   Processing unexpected handshake messages. After the link is established, this function can be invoked to
 * process the handshake messages received during user data transmission
 * @param   ctx [IN] TLS object
 * @param   data [IN] Handshake message
 * @param   len [IN] Message length
 * @param   state [IN/OUT] in:current link state, out:next link state
 *
 * @retval  HITLS_SUCCESS succeeded. The user can continue sending and receiving data.
 * @retval  For details about other error codes, see hitls_error.h
 */
int32_t HS_RecvUnexpectedMsgProcess(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, CM_State *state);

/**
 * @brief   Generate the session key
 *
 * @param   ctx [IN] TLS context
 * @param   isClient [IN] Client or Not
 *
 * @retval  HITLS_SUCCESS succeeded
 * @retval  For details about other error codes, see hitls_error.h
 */
int32_t HS_KeyEstablish(TLS_Ctx *ctx, bool isClient);

/**
 * @brief   Session recovery Generate a session key.
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS succeeded
 * @retval  For details about other error codes, see hitls_error.h
 */
int32_t HS_ResumeKeyEstablish(TLS_Ctx *ctx);

/**
 * @brief   Obtain the current handshake status
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  Current handshake status
 */
uint32_t HS_GetState(const TLS_Ctx *ctx);

/**
 * @brief Obtain the version number. If the version number is not negotiated, the latest version
 * supported by the local is returned.
 *
 * @param ctx [IN] TLS context
 *
 * @return Return the version number.
 */
uint32_t HS_GetVersion(const TLS_Ctx *ctx);

/**
 * @brief Obtain the handshake status character string.
 *
 * @param state [IN] Handshake status
 *
 * @return Character string corresponding to the handshake status
 */
const char *HS_GetStateStr(uint32_t state);

/**
 * @brief  Check whether the conditions for sending keyupdate are met
 *
 * @param ctx [IN] TLS context
 * @param updateType [IN] keyupdate type
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval  For details about other error codes, see hitls_error.h
 */
int32_t HS_CheckKeyUpdateState(const TLS_Ctx *ctx, uint32_t updateType);

/**
 * @brief   Process the keyupdate message sending process.
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS succeeded.
 * @retval  For details about other error codes, see hitls_error.h
 */
int32_t HS_SendKeyUpdate(TLS_Ctx *ctx);

/**
 * @brief  Obtain the server_name in the handshake TLS context.
 *
 * @param  ctx [IN] TLS context
 *
 * @return string of server_name in the TLS context during the handshake
 */
const char *HS_GetServerName(const TLS_Ctx *ctx);

/**
 * @brief Check whether app messages can be received.
 *
 * @param ctx [IN] TLS context
 *
 * @return true: allows receiving; false: does not allow receiving.
 */
bool HS_IsAppDataAllowed(TLS_Ctx *ctx);


int32_t HS_CheckPostHandshakeAuth(TLS_Ctx *ctx);

#ifdef __cplusplus
}
#endif
#endif /* HS_H */