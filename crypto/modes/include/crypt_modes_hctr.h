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

#ifndef CRYPT_MODES_HCTR_H
#define CRYPT_MODES_HCTR_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HCTR

#include "crypt_types.h"
#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct ModesHctrCtx MODES_HCTR_Ctx;

MODES_HCTR_Ctx *MODES_HCTR_NewCtx(int32_t algId);
MODES_HCTR_Ctx *MODES_HCTR_NewCtxEx(void *libCtx, int32_t algId);
int32_t MODES_HCTR_InitCtx(MODES_HCTR_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen,
    const uint8_t *iv, uint32_t ivLen, bool enc);
int32_t MODES_HCTR_InitCtxEx(MODES_HCTR_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen,
    const uint8_t *iv, uint32_t ivLen, void *param, bool enc);
int32_t MODES_HCTR_Update(MODES_HCTR_Ctx *modeCtx, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);
int32_t MODES_HCTR_Final(MODES_HCTR_Ctx *modeCtx, uint8_t *out, uint32_t *outLen);
int32_t MODES_HCTR_DeInitCtx(MODES_HCTR_Ctx *modeCtx);
int32_t MODES_HCTR_Ctrl(MODES_HCTR_Ctx *modeCtx, int32_t cmd, void *val, uint32_t valLen);
void MODES_HCTR_FreeCtx(MODES_HCTR_Ctx *modeCtx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_HCTR

#endif // CRYPT_MODES_HCTR_H
