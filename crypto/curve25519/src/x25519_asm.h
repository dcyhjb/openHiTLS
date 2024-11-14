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

#ifndef X25519_ASM_H
#define X25519_ASM_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_X25519

#include "curve25519_local.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Function description: out = f * g (mod p), p = 2 ^ 255 - 19, which is the modulus of curve25519 field.
 * Function prototype: void Fp51Mul(Fp51 *out, const Fp51 *f, const Fp51 *g);
 * Input register: rdi: out; rsi: f; rdx: g; fp51 is an array of [u64; 5].
 *                 rdi: out, array pointer of output parameter fp51.
 *                 rsi: pointer f of the input source data fp51 array.
 *                 rdi: pointer g of the input source data fp51 array.
 * Modify the register as follows: rax, rbx, rcx, rdx, rsp, rbp, rsi, rdi, r8-r15.
 * Output register: None
 * Function/Macro Call: None
 */
void Fp51Mul(Fp51 *out, const Fp51 *f, const Fp51 *g);

/**
 * Function description: out = f ^ 2 (mod p), p = 2 ^ 255 - 19, which is the modulus of curve25519 field.
 * Function prototype: void Fp51Square(Fp51 *out, const Fp51 *f);
 * Input register: rdi: out; rsi: f; fp51 is an array of [u64; 5]
 *                 rdi: out, array pointer of output parameter fp51.
 *                 rsi: pointer f of the input source data fp51 array.
 * Modify the register as follows: rax, rbx, rcx, rdx, rsp, rbp, rsi, rdi, r8-r15.
 * Output register: None
 * Function/Macro Call: None
 */
void Fp51Square(Fp51 *out, const Fp51 *f);

/**
 * Function description: out = f * 121666 (mod p), p = 2 ^ 255 - 19, which is the modulus of curve25519 field.
 * Function prototype: void Fp51MulScalar(Fp51 *out, const Fp51 *f, const uint32_t scalar);
 * Input register: rdi: out; rsi: f; fp51 is an array of [u64; 5]
 *                 rdi: out, array pointer of output parameter fp51.
 *                 rsi: pointer f of the input source data fp51 array.
 * Modify the register as follows: rax, rbx, rcx, rdx, rsp, rbp, rsi, rdi, r8-r15.
 * Output register: None
 * Function/Macro Call: None
 */
void Fp51MulScalar(Fp51 *out, const Fp51 *in);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_CURVE25519

#endif // X25519_ASM_H
