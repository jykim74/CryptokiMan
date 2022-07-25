#ifndef COMMON_H
#define COMMON_H

#include <QStringList>
#include <QWidget>
#include "js_pkcs11.h"

enum {
    OBJ_DATA_IDX = 0,
    OBJ_CERT_IDX,
    OBJ_PUBKEY_IDX,
    OBJ_PRIKEY_IDX,
    OBJ_SECRET_IDX
};

static QStringList kObjectList = {
    "Data", "Certificate", "PublicKey", "PrivateKey", "SecretKey"
};

enum { JS_FILE_TYPE_CERT,
       JS_FILE_TYPE_PRIKEY,
       JS_FILE_TYPE_TXT,
       JS_FILE_TYPE_BER,
       JS_FILE_TYPE_DLL,
       JS_FILE_TYPE_PFX };

static QStringList kCommonAttList = {
    "CKA_LABEL", "CKA_ID", "CKA_MODIFIABLE", "CKA_TOKEN",
};

static QStringList kCertAttList = {
    "CKA_SUBJECT", "CKA_VALUE", "CKA_TRUSTED", "CKA_PRIVATE",
    "CKA_START_DATE", "CKA_END_DATE",
};

static QStringList kPubKeyAttList = {
    "CKA_MODULUS", "CKA_PUBLIC_EXPONENT", "CKA_TOKEN", "CKA_WRAP",
    "CKA_ENCRYPT", "CKA_VERIFY", "CKA_PRIVATE", "CKA_DERIVE",
    "CKA_ECDSA_PARAMS", "CKA_EC_POINT", "CKA_START_DATE", "CKA_END_DATE",
};

static QStringList kPriKetAttList = {
    "CKA_SUBJECT", "CKA_MODULUS", "CKA_PUBLIC_EXPONENT", "CKA_PRIVATE_EXPONENT",
    "CKA_PRIME_1", "CKA_PRIME_2", "CKA_EXPONENT_1", "CKA_EXPONENT_2",
    "CKA_ECDSA_PARAMS", "CKA_EC_POINT", "CKA_SENSITIVE", "CKA_UNWARP",
    "CKA_SIGN", "CKA_DECRYPT", "CKA_DERIVE", "CKA_EXTRACTABLE",
    "CKA_START_DATE", "CKA_END_DATE",
};

static QStringList kSecretKeyAttList = {
    "CKA_PRIVATE", "CKA_SENSITIVE", "CKA_ENCRYPT", "CKA_DECRYPT",
    "CKA_SIGN", "CKA_VERIFY", "CKA_WRAP", "CKA_UNWRAP",
    "CKA_DERIVE", "CKA_EXTRACTABLE", "CKA_VALUE", "CKA_VALUE_LEN",
    "CKA_START_DATE", "CKA_END_DATE",
};

static QStringList kDataAttList = {
    "CKA_VALUE", "CKA_PRIVATE",
};

QString findFile( QWidget *parent, int nType, const QString strPath );
void getCKDate( const QDate date, CK_DATE *pCKDate );
QString getBool( const BIN *pBin );
QString getHexString( unsigned char *pData, int nDataLen );

#endif // COMMON_H
