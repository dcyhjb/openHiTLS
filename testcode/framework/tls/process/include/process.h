/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef PROCESS_H
#define PROCESS_H

#include "hlt_type.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DOMAIN_PATH_LEN (128)
#define TLS_RES_MAX_NUM (64)

typedef struct ProcessSt {
    TLS_TYPE tlsType; // Identifies whether the HiTLS interface is used.
    char srcDomainPath[DOMAIN_PATH_LEN];
    char peerDomainPath[DOMAIN_PATH_LEN]; // This field is used only by remote processes.
    int controlChannelFd; // This field is used only by the local process.
    int remoteFlag; // Indicates whether the process is a remote process. The value 1 indicates a remote process.
    int connFd; // FD used by the TLS link
    int connType; // Enumerated value of HILT_TransportType, which is the communication protocol type used by the TLS link.
    int connPort;
    struct sockaddr_in sockAddr;
    void* tlsResArray[TLS_RES_MAX_NUM]; // Stores ctx SSL resources.
    int tlsResNum; // Number of created TLS resources
    void* hltTlsResArray[TLS_RES_MAX_NUM]; // Stores the HLT_Tls_Res resource. This resource is used only by the local process.
    int hltTlsResNum; // Number of created HLT_Tls_Res resources.
} Process;

/**
* @brief  Initializes the global table used to represent command IDs.
*/
void InitCmdIndex();

/**
* @brief  Initializing Process Resources
*/
int InitProcess(void);

/**
* @brief  Obtaining Process Resources
*/
Process* GetProcess();

/**
* @brief  Obtain the process from the linked list.
*/
Process* GetProcessFromList();

/**
* @brief  Release the linked list of the storage process.
*/
void FreeProcessResList();

/**
* @brief  Release process resources.
*/
void FreeProcess();

#ifdef __cplusplus
}
#endif

#endif // PROCESS_H