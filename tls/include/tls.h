/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef TLS_H
#define TLS_H

#include <stdint.h>
#include <stdbool.h>
#include "cipher_suite.h"
#include "tls_config.h"
#include "hitls_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DIGEST_SIZE 64UL /* The longest known value is SHA512 */

#define DTLS_DEFAULT_PMTU 1500uL

/* RFC 6083 4.1. Mapping of DTLS Records:
    The supported maximum length of SCTP user messages MUST be at least
    2^14 + 2048 + 13 = 18445 bytes (2^14 + 2048 is the maximum length of
    the DTLSCiphertext.fragment, and 13 is the size of the DTLS record
    header). */
#define DTLS_SCTP_PMTU 18445uL

#define IS_DTLS_VERSION(version) (((version) & 0x8u) == 0x8u)

#define MAC_KEY_LEN 32u              /* the length of mac key */

#define UNPROCESSED_APP_MSG_COUNT_MAX 50       /* number of APP data cached */

#define RANDOM_SIZE 32u                   /* the size of random number */

typedef struct TlsCtx TLS_Ctx;
typedef struct HsCtx HS_Ctx;
typedef struct CcsCtx CCS_Ctx;
typedef struct AlertCtx ALERT_Ctx;
typedef struct RecCtx REC_Ctx;
typedef struct AppDataCtx APP_Ctx;

typedef enum {
    CCS_CMD_RECV_READY,                 /* CCS allowed to be received */
    CCS_CMD_RECV_EXIT_READY,            /* CCS cannot be received */
    CCS_CMD_RECV_ACTIVE_CIPHER_SPEC,    /* CCS active change cipher spec */
} CCS_Cmd;

/* Check whether the CCS message is received */
typedef bool (*IsRecvCcsCallback)(const TLS_Ctx *ctx);
/* Send a CCS message */
typedef int32_t (*SendCcsCallback)(TLS_Ctx *ctx);
/* Control the CCS */
typedef int32_t (*CtrlCcsCallback)(TLS_Ctx *ctx, CCS_Cmd cmd);

typedef enum {
    ALERT_LEVEL_WARNING = 1,
    ALERT_LEVEL_FATAL = 2,
    ALERT_LEVEL_UNKNOWN = 255,
} ALERT_Level;

typedef enum {
    ALERT_CLOSE_NOTIFY = 0,
    ALERT_UNEXPECTED_MESSAGE = 10,
    ALERT_BAD_RECORD_MAC = 20,
    ALERT_DECRYPTION_FAILED = 21,
    ALERT_RECORD_OVERFLOW = 22,
    ALERT_DECOMPRESSION_FAILURE = 30,
    ALERT_HANDSHAKE_FAILURE = 40,
    ALERT_NO_CERTIFICATE_RESERVED = 41,
    ALERT_BAD_CERTIFICATE = 42,
    ALERT_UNSUPPORTED_CERTIFICATE = 43,
    ALERT_CERTIFICATE_REVOKED = 44,
    ALERT_CERTIFICATE_EXPIRED = 45,
    ALERT_CERTIFICATE_UNKNOWN = 46,
    ALERT_ILLEGAL_PARAMETER = 47,
    ALERT_UNKNOWN_CA = 48,
    ALERT_ACCESS_DENIED = 49,
    ALERT_DECODE_ERROR = 50,
    ALERT_DECRYPT_ERROR = 51,
    ALERT_EXPORT_RESTRICTION_RESERVED = 60,
    ALERT_PROTOCOL_VERSION = 70,
    ALERT_INSUFFICIENT_SECURITY = 71,
    ALERT_INTERNAL_ERROR = 80,
    ALERT_INAPPROPRIATE_FALLBACK = 86,
    ALERT_USER_CANCELED = 90,
    ALERT_NO_RENEGOTIATION = 100,
    ALERT_MISSING_EXTENSION = 109,
    ALERT_UNSUPPORTED_EXTENSION = 110,
    ALERT_CERTIFICATE_UNOBTAINABLE = 111,
    ALERT_UNRECOGNIZED_NAME = 112,
    ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
    ALERT_BAD_CERTIFICATE_HASH_VALUE = 114,
    ALERT_UNKNOWN_PSK_IDENTITY = 115,
    ALERT_CERTIFICATE_REQUIRED = 116,
    ALERT_NO_APPLICATION_PROTOCOL = 120,
    ALERT_UNKNOWN = 255
} ALERT_Description;

/** Connection management state */
typedef enum {
    CM_STATE_IDLE,
    CM_STATE_HANDSHAKING,
    CM_STATE_TRANSPORTING,
    CM_STATE_RENEGOTIATION,
    CM_STATE_ALERTING,
    CM_STATE_ALERTED,
    CM_STATE_CLOSED,
    CM_STATE_END
} CM_State;

/** post-handshake auth */
typedef enum {
    PHA_NONE,           /* not support pha */
    PHA_EXTENSION,      /* pha extension send or received */
    PHA_PENDING,        /* try to send certificate request */
    PHA_REQUESTED       /* certificate request has been sent or received */
} PHA_State;


typedef void (*SendAlertCallback)(TLS_Ctx *ctx, ALERT_Level level, ALERT_Description description);

typedef bool (*GetAlertFlagCallback)(const TLS_Ctx *ctx);

typedef int32_t (*UnexpectMsgHandleCallback)(TLS_Ctx *ctx, uint32_t msgType, const uint8_t *data, uint32_t dataLen);

/** Connection management configure */
typedef struct TLSCtxConfig {
    void *userData;                         /* user data */
    uint16_t pmtu;                          /* Maximum transport unit of a path (bytes) */
    uint8_t reserved[1];                    /* four-byte alignment */
    TLS_Config tlsConfig;                   /* tls configure context */
} TLS_CtxConfig;

typedef struct {
    uint32_t algRemainTime;            /* current key usage times */
    uint8_t preMacKey[MAC_KEY_LEN];    /* previous random key */
    uint8_t macKey[MAC_KEY_LEN];       /* random key used by the current algorithm */
} CookieInfo;

typedef struct {
    uint16_t version;                              /* negotiated version */
    uint16_t clientVersion;                        /* version field of client hello */
    uint32_t cookieSize;                           /* cookie length */
    uint8_t *cookie;                               /* cookie data */
    CookieInfo cookieInfo;                         /* cookie info with calculation and verification */
    CipherSuiteInfo cipherSuiteInfo;               /* cipher suite info */
    HITLS_SignHashAlgo signScheme;                 /* sign algorithm used by the local */
    uint8_t *alpnSelected;                         /* alpn proto */
    uint32_t alpnSelectedSize;
    uint8_t clientVerifyData[MAX_DIGEST_SIZE];     /* client verify data */
    uint8_t serverVerifyData[MAX_DIGEST_SIZE];     /* server verify data */
    uint8_t clientRandom[RANDOM_SIZE];             /* client random number */
    uint8_t serverRandom[RANDOM_SIZE];             /* server random number */
    uint32_t clientVerifyDataSize;                 /* client verify data size */
    uint32_t serverVerifyDataSize;                 /* server verify data size */
    uint32_t renegotiationNum;                     /* the number of renegotiation */
    uint32_t certReqSendTime;                      /* certificate request sending times */
    uint32_t tls13BasicKeyExMode;                   /* TLS13_KE_MODE_PSK_ONLY || TLS13_KE_MODE_PSK_WITH_DHE ||
                                                      TLS13_CERT_AUTH_WITH_DHE */

    uint16_t negotiatedGroup;                      /* negotiated group */
    bool isResume;                                 /* whether to resume the session */
    bool isRenegotiation;                          /* whether to renegotiate */

    bool isSecureRenegotiation;                    /* whether security renegotiation */
    bool isExtendedMasterSecret;                   /* whether to calculate the extended master sercret */
    bool isEncryptThenMac;                         /* Whether to enable EncryptThenMac */
    bool isEncryptThenMacRead;                     /* Whether to enable EncryptThenMacRead */
    bool isEncryptThenMacWrite;                    /* Whether to enable EncryptThenMacWrite */
    bool isTicket;                                 /* whether to negotiate tickets, only below tls1.3 */
    bool isSniStateOK;                             /* Whether server successfully processes the server_name callback */
} TLS_NegotiatedInfo;

typedef struct {
    uint16_t *groups;                   /* all groups sent by the peer end */
    uint32_t groupsSize;                /* size of a group */
    HITLS_SignHashAlgo peerSignHashAlg; /* peer signature algorithm */
    HITLS_ERROR verifyResult;           /* record the certificate verification result of the peer end */
    HITLS_TrustedCAList *caList;        /* peer trusted ca list */
} PeerInfo;

struct TlsCtx {
    bool isClient;                          /* is Client */
    bool userShutDown;                      /* record whether the local end invokes the HITLS_Close */
    bool userRenego;                        /* record whether the local end initiates renegotiation */
    uint8_t rwstate;                        /* record the current internal read and write state */
    CM_State preState;
    CM_State state;

    uint32_t shutdownState;                 /* Record the shutdown state */

    void *rUio;                             /* read uio */
    void *uio;                              /* write uio */
    void *bUio;                             /* Storing uio */
    HS_Ctx *hsCtx;                          /* handshake context */
    CCS_Ctx *ccsCtx;                        /* ChangeCipherSpec context */
    ALERT_Ctx *alertCtx;                    /* alert context */
    REC_Ctx *recCtx;                        /* record context */
    APP_Ctx *appCtx;                        /* app context */
    struct {
        IsRecvCcsCallback isRecvCCS;
        SendCcsCallback sendCCS;            /* send a CCS message */
        CtrlCcsCallback ctrlCCS;            /* controlling CCS */
        SendAlertCallback sendAlert;        /* set the alert message to be sent */
        GetAlertFlagCallback getAlertFlag;  /* get alert state */
        UnexpectMsgHandleCallback unexpectedMsgProcessCb;   /* the callback for unexpected messages */
    } method;

    PeerInfo peerInfo;                      /* Temporarily save the messages sent by the peer end */
    TLS_CtxConfig config;                   /* private configuration */
    TLS_Config *globalConfig;               /* global configuration */
    TLS_NegotiatedInfo negotiatedInfo;      /* TLS negotiation information */
    HITLS_Session *session;                 /* session information */

    uint8_t clientAppTrafficSecret[MAX_DIGEST_SIZE];   /* TLS1.3 client app traffic secret */
    uint8_t serverAppTrafficSecret[MAX_DIGEST_SIZE];   /* TLS1.3 server app traffic secret */
    uint8_t resumptionMasterSecret[MAX_DIGEST_SIZE];   /* TLS1.3 session resume secret */

    uint32_t bytesLeftToRead;               /* bytes left to read after hs header has parsed */
    uint32_t keyUpdateType;                 /* TLS1.3 key update type */
    bool isKeyUpdateRequest;                /* TLS1.3 Check whether there are unsent key update messages */
    bool haveClientPointFormats;            /* whether the EC point format extension in the client hello is processed */
    bool hasParsedHsMsgHeader;              /* has parsed current hs msg header */
    int32_t errorCode;                      /* Record the tls error code */

    HITLS_HASH_Ctx *phaHash;                /* tls1.3 pha: Handshake main process hash */
    HITLS_HASH_Ctx *phaCurHash;             /* tls1.3 pha: Temporarily store the current pha hash */
    PHA_State phaState;                     /* tls1.3 pha state */
    uint8_t *certificateReqCtx;             /* tls1.3 pha certificate_request_context */
    uint32_t certificateReqCtxSize;         /* tls1.3 pha certificate_request_context */
};

#ifdef __cplusplus
}
#endif

#endif /* TLS_H */
