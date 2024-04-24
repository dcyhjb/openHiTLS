/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef RPC_FUNC_H
#define RPC_FUNC_H

#include <pthread.h>

#include "handle_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *funcId;
    int (*hfunc)(CmdData *cmdData);
} RpcFunList;

/**
* @brief Obtain the list of registered functions.
*/
RpcFunList* GetRpcFuncList();

/**
* @brief Obtain the number of registered functions.
*/
int GetRpcFuncNum();

/**
* @brief Invoke the RPC to create CTX resources.
*/
int RpcTlsNewCtx(CmdData*);

/**
* @brief Invoke the RPC to set the CTX information.
*/
int RpcTlsSetCtx(CmdData*);

/**
* @brief Invoke the RPC to create an SSL resource.
*/
int RpcTlsNewSsl(CmdData*);

/**
* @brief Invoke the RPC to set the SSL information.
*/
int RpcTlsSetSsl(CmdData*);

/**
* @brief The RPC invokes the TLS connection to be listened on.
*/
int RpcTlsListen(CmdData *cmdData);

/**
* @brief Invoke the RPC to wait for the TLS connection.
*/
int RpcTlsAccept(CmdData*);

/**
* @brief Invoke the RPC interface for TLS connection.
*/
int RpcTlsConnect(CmdData*);

/**
* @brief Invoke the RPC to read data through TLS.
*/
int RpcTlsRead(CmdData *cmdData);

/**
* @brief Invoke the RPC to write data through TLS.
*/
int RpcTlsWrite(CmdData *cmdData);

/**
* @brief Invoke the RPC interface to enable renegotiation.
*/
int RpcTlsRenegotiate(CmdData *cmdData);

/**
* @brief The RPC call is used to enable the pha.
*/
int RpcTlsVerifyClientPostHandshake(CmdData *cmdData);

/**
* @brief  The RPC exits the process
*/
int RpcProcessExit(CmdData*);

/**
* @brief RPC bound port
*/
int RunDataChannelBind(void *param);

/**
* @brief RPC listening data connection
*/
int RpcDataChannelAccept(CmdData*);

/**
* @brief The RPC data initiates a connection.
*/
int RpcDataChannelConnect(CmdData *cmdData);

/**
* @brief RPC listens on a certain type of data connection.
*/
int RunDataChannelAccept(void *param);

/**
* @brief RPC bound port
*/
int RpcDataChannelBind(CmdData *cmdData);

/**
* @brief RPC registration hook
*/
int RpcTlsRegCallback(CmdData *cmdData);

/**
* @brief RPC Obtain the SSL connection status.
*/
int RpcTlsGetStatus(CmdData *cmdData);

/**
* @brief RPC Obtain the flag of the alert message.
*/
int RpcTlsGetAlertFlag(CmdData *cmdData);

/**
* @brief RPC Obtain the level of the alert message.
*/
int RpcTlsGetAlertLevel(CmdData *cmdData);

/**
* @brief RPC Obtain the description of the alert message.
*/
int RpcTlsGetAlertDescription(CmdData *cmdData);

/**
* @brief RPC Disable the TLS connection.
*/
int RpcTlsClose(CmdData *cmdData);

/**
* @brief RPC Release the CTX and SSL contexts.
*/
int RpcFreeResFormSsl(CmdData *cmdData);

/**
* @brief RPC Disable the SCTP connection.
*/
int RpcSctpClose(CmdData *cmdData);

int RpcCloseFd(CmdData *cmdData);

int RpcTlsSetMtu(CmdData *cmdData);

int RpcTlsGetErrorCode(CmdData *cmdData);

#ifdef __cplusplus
}
#endif

#endif // RPC_FUNC_H
