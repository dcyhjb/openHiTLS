/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */
/* INCLUDE_BASE test_suite_tls12_consistency_rfc5246 */
#include <stdio.h>
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "tls.h"
#include "cert.h"
#include "securec.h"
#include "frame_msg.h"
#include "alert.h"
#include "bsl_list.h"
#include "app_ctx.h"
/* END_HEADER */

#define g_uiPort 45678


/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_SEND_CERTFICATE_TC001 rfc 5246 table row 51
* @title  If the server has sent a CertificateRequest message, the client must send a certificate message.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server, and enable the dual-end verification. Expected result 1 is obtained.
*         2. The client initiates a TLS over TCP link request. After the server receives the CertificateRequest message, expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The client is in the TRY_SEND_CLIENT_KEY_EXCHANGE state, and the server is in the TRY_RECV_CERTIFICATIONATE state.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_SEND_CERTFICATE_TC001(void)
{
    /* Use the default configuration items to configure the client and server, and enable the dual-end verification. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_SEND_SERVER_HELLO_DONE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO_DONE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);

    // The client initiates a TLS over TCP link request.
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(testInfo.client->ssl->hsCtx->state, TRY_SEND_CLIENT_KEY_EXCHANGE);

    uint32_t readLen = 0;
    uint8_t tmp1[MAX_RECORD_LENTH] = {0};
    uint32_t tmp1Len = sizeof(tmp1);
    ASSERT_TRUE(FRAME_TransportSendMsg(testInfo.client->io, tmp1, tmp1Len, &readLen) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    uint8_t tmp2[MAX_RECORD_LENTH] = {0};
    uint32_t tmp2Len = sizeof(tmp2);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, tmp2, tmp2Len) == HITLS_SUCCESS);

    ASSERT_TRUE(testInfo.server->ssl->hsCtx->state == TRY_RECV_CERTIFICATE);

exit:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_SIGNATION_NOT_SUITABLE_CERT_TC002
* @title During dual-end verification, the server signature algorithm does not match the certificate signature algorithm. As a result, the link fails to be established.
* @precon nan
* @brief    1. Configure dual-end verification. Set the signature algorithm to RSA_PKCS1_SHA256, cipher suite to RSA, certificate to RSA, and certificate signature to ECDSA_SHA256 on the server. Expected result 1 is obtained.
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_SIGNATION_NOT_SUITABLE_CERT_TC002(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    // 1. Configure dual-end verification. Set the signature algorithm to RSA_PKCS1_SHA256, cipher suite to RSA, certificate to RSA, and certificate signature to ECDSA_SHA256 on the server.
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
    uint32_t signAlgsSize = sizeof(signAlgs) / sizeof(uint16_t);
    HITLS_CFG_SetSignature(config, signAlgs, signAlgsSize);
    HITLS_CFG_SetClientVerifySupport(config, true);
    uint16_t cipherSuites[] = {HITLS_RSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(config, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));
    FRAME_CertInfo certInfoServer = {
        "ecdsa/root.pem",
        "rsa_sha/intca.pem",
        "rsa_sha/RSA2048SHA256.pem",
        0,
        "rsa_sha/RSA2048SHA256.key.pem",
        0,
    };
    FRAME_CertInfo certInfoClient = {
        "rsa_sha/root.pem",
        "ecdsa/intca.pem",
        "ecdsa/ec_app256SHA256.pem",
        0,
        "ecdsa/ec_app256SHA256.key.pem",
        0,
    };
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);


    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);
exit:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC003
* @title During dual-end verification, the intermediate certificate is incorrectly configured on the client. As a result, the verification on the server fails.
* @precon nan
* @brief    1. Configure dual-ended authentication. Configure a correct terminal certificate and an incorrect intermediate certificate on the client. Configure a correct certificate chain on the server. Check whether the server fails the authentication. Expected result 1 is obtained.
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC003(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_CFG_SetClientVerifySupport(config, true);
    // 1. Configure dual-ended authentication. Configure a correct terminal certificate and an incorrect intermediate certificate on the client. Configure a correct certificate chain on the server. Check whether the server fails the authentication.
    FRAME_CertInfo certInfoClient = {
        "ecdsa/root.pem",
        "rsa_sha/intca.pem",
        "ecdsa/ec_app256SHA256.pem",
        0,
        "ecdsa/ec_app256SHA256.key.pem",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        "ecdsa/root.pem",
        "ecdsa/intca.pem",
        "ecdsa/ec_app256SHA256.pem",
        0,
        "ecdsa/ec_app256SHA256.key.pem",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);
exit:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_NEGOTIATE_SIGNATION_FAIL_TC001
* @title Link setup failed because the signature algorithm does not match.
* @precon nan
* @brief    1. Set the client signature algorithm to ECDSA_SECP256R1_SHA256 and the server certificate signature algorithm to RSA_SHA256. Expected result 1 is obtained.
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_NEGOTIATE_SIGNATION_FAIL_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    uint32_t signAlgsSize = sizeof(signAlgs) / sizeof(uint16_t);
    FRAME_CertInfo certInfo = {
        "rsa_sha/root.pem:rsa_sha/intca.pem",
        "rsa_sha/intca.pem",
        "rsa_sha/RSA2048SHA256.pem",
        0,
        "rsa_sha/RSA2048SHA256.key.pem",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);
    // 1. Set the client signature algorithm to ECDSA_SECP256R1_SHA256 and the server certificate signature algorithm to RSA_SHA256.
    ASSERT_TRUE(HITLS_SetSigalgsList(client->ssl, signAlgs, signAlgsSize) == HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);
exit:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_SIGNATION_NOT_SUITABLE_CERT_TC001
* @title The certificate signature algorithm does not match the signature algorithm set on the client. As a result, the link fails to be established.
* @precon nan
* @brief    1. Set the signature algorithm to RSA_PKCS1_SHA256 on the client, cipher suite to RSA, certificate to RSA,
                server signature algorithm to RSA_PKCS1_SHA256, and certificate signature algorithm to ECDSA_SHA256.
                Expected Certificate Verification Failure (Failed to Select a Certificate on the Server)
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_SIGNATION_NOT_SUITABLE_CERT_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    // 1. Set the signature algorithm to RSA_PKCS1_SHA256 on the client, cipher suite to RSA, certificate to RSA,
    //     server signature algorithm to RSA_PKCS1_SHA256, and certificate signature algorithm to ECDSA_SHA256.
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
    uint32_t signAlgsSize = sizeof(signAlgs) / sizeof(uint16_t);
    HITLS_CFG_SetSignature(config, signAlgs, signAlgsSize);
    HITLS_CFG_SetClientVerifySupport(config, true);
    uint16_t cipherSuites[] = {HITLS_RSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(config, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));
    FRAME_CertInfo certInfoClient = {
        "ecdsa/root.pem",
        "rsa_sha/intca.pem",
        "rsa_sha/RSA2048SHA256.pem",
        0,
        "rsa_sha/RSA2048SHA256.key.pem",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        "rsa_sha/root.pem",
        "ecdsa/intca.pem",
        "ecdsa/ec_app256SHA256.pem",
        0,
        "ecdsa/ec_app256SHA256.key.pem",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);
exit:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC004
* @title During dual-end authentication, the client certificate is out of order, and the link fails to be established.
* @precon nan
* @brief    1. Configure dual-end verification. Configure the first certificate on the client as an intermediate
                certificate and the second certificate as a terminal certificate. Configure a correct certificate chain
                on the server. Check whether the verification fails on the server. Expected result 1 is obtained.
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC004(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_CFG_SetClientVerifySupport(config, true);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE), HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    // Change the certificate sequence. The intermediate certificate is used first, and then the device certificate is used.
    // 1. Configure dual-end authentication. Configure the first certificate on the client as an intermediate
    // certificate, and the second certificate as a terminal certificate. Configure a correct certificate chain on the server.
    frameMsg.body.hsMsg.body.certificate.certItem->cert.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.certificate.certItem->certLen.state = ASSIGNED_FIELD;
    struct FrameCertItem_ *tmp = frameMsg.body.hsMsg.body.certificate.certItem->next;
    frameMsg.body.hsMsg.body.certificate.certItem->next = tmp->next; // a->c
    tmp->next = frameMsg.body.hsMsg.body.certificate.certItem; // b -> a
    frameMsg.body.hsMsg.body.certificate.certItem = tmp;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_PARSE_VERIFY_SIGN_FAIL);
exit:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


static int32_t STUB_SAL_CERT_KeyDecrypt_Fail(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    (void)cipher;
    (void)in;
    (void)inLen;
    (void)out;
    (void)outLen;
    return HITLS_CRYPT_ERR_DECRYPT;
}

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_DECRYPT_FAIL_TC005
* @title After the premasterkey to be received by the server is modified, the connection fails to be established.
* @precon nan
* @brief    1. Configure the RSA cipher suite. When the server receives the premasterkey, change the value of the
            premasterkey and construct a decryption failure scenario. It is expected that CCS messages are sent normally
            and the link fails to be established. Expected result 1 is obtained.
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_DECRYPT_FAIL_TC005(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_CFG_SetClientVerifySupport(config, true);
    // 1.Configure the RSA cipher suite. Change the value of the premasterkey when the server receives the premasterkey.
    // Construct a decryption failure scenario. The CCS message is expected to be sent normally.
    uint16_t cipherSuits[] = {HITLS_RSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);

    STUB_Init();
    FuncStubInfo tmpStubInfo;
    STUB_Replace(&tmpStubInfo, SAL_CERT_KeyDecrypt, STUB_SAL_CERT_KeyDecrypt_Fail);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    STUB_Reset(&tmpStubInfo);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_REC_BAD_RECORD_MAC);
    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(server->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertInfo.description, ALERT_BAD_RECORD_MAC);

exit:

    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_KEYUSAGE_CERT_TC003
* @title The certificate carries the correct keyuage extension, and the link is successfully established.
* @precon nan
* @brief    1. Configure the server certificate with the keyuage extension and support digitalSignature. The link is successfully established. Expected result 1 is obtained.
* @expect   1. The link is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_KEYUSAGE_CERT_TC003(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_CFG_SetClientVerifySupport(config, true);
    // 1. Set the server certificate with the keyuage extension and support digitalSignature.
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

exit:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_RENEGOTIATION_UNSUPPORTED_TC001
* @title Invoke the hitls_connect/hitls_accept interface to initiate renegotiation. The peer end does not support renegotiation.
* @precon nan
* @brief    1. Invoke the hitls_renegotiate interface to initiate renegotiation. Expected result 1 is obtained.
            2. Invoke the hitls_connect/hitls_accept interface to initiate renegotiation. The peer end does not support renegotiation. Expected result 2 is obtained.
* @expect   1. The link enters the renegotiation state.
            2. The peer end returns a warning alert.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RENEGOTIATION_UNSUPPORTED_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    HITLS_SetRenegotiationSupport(client->ssl, true);

    // 1. Invoke the hitls_renegotiate interface to initiate renegotiation.
    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    // Invoke the hitls_connect/hitls_accept interface to initiate renegotiation. The peer end does not support renegotiation.
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(client->ssl->state, CM_STATE_RENEGOTIATION);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    // Send a warning alert and ALERT_NO_RENEGOTIATION message. After receiving the message, the peer end changes the status to CM_STATE_TRANSPORTING.
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

exit:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

int32_t RecParseInnerPlaintext(TLS_Ctx *ctx, const uint8_t *text, uint32_t *textLen, uint8_t *recType);

int32_t STUB_RecParseInnerPlaintext(TLS_Ctx *ctx, const uint8_t *text, uint32_t *textLen, uint8_t *recType)
{
    (void)ctx;
    (void)text;
    (void)textLen;
    *recType = (uint8_t)REC_TYPE_APP;

    return HITLS_SUCCESS;
}
/* @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_RENEGOTIATION_UNSUPPORTED_TC002
* @title Invoke the hitls_connect/hitls_accept/hitls_write interface to initiate renegotiation, and the peer end returns an app message.
* @precon  nan
* @brief    1. Invoke the hitls_renegotiate interface to initiate renegotiation. Expected result 1 is displayed.
            2. Invoke the hitls_connect/hitls_accept/hitls_write interface to initiate renegotiation. The peer end replies with an app message. Expected result 2 is obtained.
            3. The peer end continuously sends 51 app messages. Expected result 3 is obtained.
            4. Read the stored app message. Expected result 4 is obtained.
* @expect   1. The link enters the renegotiation state.
            2. Received successfully.
            3. Received successfully.
            4. The 50th message can be read normally, and the 51st message is lost.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RENEGOTIATION_UNSUPPORTED_TC002()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config->isSupportRenegotiation = true;

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    // 1. Invoke the hitls_renegotiate interface to initiate renegotiation.
    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    // 2. Invoke the hitls_connect/hitls_accept/hitls_write interface to initiate renegotiation. The peer end replies with an app message.
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    uint8_t data[] = "Hello World";
    int32_t count = 0;
    while (count < 60) {
        // 3. The peer end continuously sends 51 app messages.
        int32_t ret = HITLS_Write(server->ssl, data, sizeof(data));
        ASSERT_TRUE(ret == HITLS_SUCCESS);
        ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
        ret = HITLS_Connect(client->ssl);
        count++;
        if (ret == HITLS_SUCCESS) {
            // 4. Read the stored app message.
            APP_Ctx *appCtx = client->ssl->appCtx;
            if (count <= UNPROCESSED_APP_MSG_COUNT_MAX) {
                ASSERT_TRUE(BSL_LIST_COUNT(appCtx->appList) == count);
            } else {
                ASSERT_TRUE(BSL_LIST_COUNT(appCtx->appList) == UNPROCESSED_APP_MSG_COUNT_MAX);
            }
        }
    }

exit:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */