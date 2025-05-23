/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef CMVP_COMMON_H
#define CMVP_COMMON_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CMVP

#include <stdint.h>
#include <stdbool.h>
#include <syslog.h>
#include "crypt_cmvp.h"
#include "crypt_types.h"
#include "crypt_algid.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CMVP_MODE_NOT_APPROVED 0
#define CMVP_MODE_ISO 1
#define CMVP_MODE_FIPS 2
#define CMVP_MODE_NDCPP 3
#define CMVP_MODE_GM 4

#ifndef HITLS_CRYPTO_CMVP_MODE
#define HITLS_CRYPTO_CMVP_MODE CMVP_MODE_ISO
#endif


void CMVP_CspFlagSet(bool flag); // Sets whether the CSP exists in the memory.
bool CMVP_CspFlagGet(void);      // Check whether the CSP exists in the memory. true: yes; false: no.

int32_t CMVP_ModeSet(CRYPT_CMVP_MODE mode); // Setting the Mode

uint8_t *CMVP_StringsToBins(const char *in, uint32_t *outLen); // Converting a hexadecimal string to a buf array
void CMVP_WriteSyslog(const char *ident, int32_t priority, const char *format, ...)
    __attribute__((format(printf, 3, 4))); // Write syslog
char *CMVP_ReadFile(const char *path, const char *mode, uint32_t *bufLen); // Read file
char *CMVP_GetLibPath(void *func); // Obtaining the Library Path

int32_t CMVP_CheckIntegrity(CRYPT_MAC_AlgId macId);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif
#endif // CMVP_COMMON_H
