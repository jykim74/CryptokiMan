#ifndef COMMON_H
#define COMMON_H

#include <QStringList>
#include <QWidget>
#include "js_pkcs11.h"
#include "js_pki_ext.h"

#define     HM_ITEM_TYPE_ROOT               0
#define     HM_ITEM_TYPE_SLOT               1
#define     HM_ITEM_TYPE_TOKEN              2
#define     HM_ITEM_TYPE_MECHANISM          3
#define     HM_ITEM_TYPE_SESSION            4
#define     HM_ITEM_TYPE_OBJECTS            5
#define     HM_ITEM_TYPE_CERTIFICATE        6
#define     HM_ITEM_TYPE_PUBLICKEY          7
#define     HM_ITEM_TYPE_PRIVATEKEY         8
#define     HM_ITEM_TYPE_SECRETKEY          9
#define     HM_ITEM_TYPE_DATA               10

/*
#define     HM_ITEM_TYPE_CERTIFICATE_OBJECT 11
#define     HM_ITEM_TYPE_PUBLICKEY_OBJECT   12
#define     HM_ITEM_TYPE_PRIVATEKEY_OBJECT  13
#define     HM_ITEM_TYPE_SECRETKEY_OBJECT   14
#define     HM_ITEM_TYPE_DATA_OBJECT        15
*/

enum {
    DATA_STRING,
    DATA_HEX,
    DATA_BASE64,
    DATA_URL
};

enum {
    OBJ_CERT_IDX = 0,
    OBJ_PUBKEY_IDX,
    OBJ_PRIKEY_IDX,
    OBJ_SECRET_IDX,
    OBJ_DATA_IDX
};

static QStringList kObjectTypeList = {
    "Certificate", "PublicKey", "PrivateKey", "SecretKey", "Data"
};

enum { JS_FILE_TYPE_CERT,
       JS_FILE_TYPE_PRIKEY,
       JS_FILE_TYPE_TXT,
       JS_FILE_TYPE_BER,
       JS_FILE_TYPE_BIN,
       JS_FILE_TYPE_DLL,
       JS_FILE_TYPE_PFX };

const QString kTableStyle = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";

const QStringList kLogLevel = { "None", "Error", "Info", "Warn", "Debug" };


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
    "CKA_ECDSA_PARAMS", "CKA_VALUE", "CKA_SENSITIVE", "CKA_UNWARP",
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

static QStringList kSecretWrapMech = {
    "CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_PAD"
};

static QStringList kRSAWrapMech = {
    "CKM_RSA_PKCS", "CKM_RSA_PKCS_OAEP",
};

static QStringList kWrapType = {
    "Secret", "RSA"
};

static QStringList kECCOptionList = { "prime256v1",
    "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
    "secp160r1", "secp160r2", "secp192r1", "secp192k1", "secp224k1",
    "secp224r1", "secp256k1", "secp384r1", "secp521r1",
    "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1",
    "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1",
    "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1",
    "sect409r1", "sect571k1", "sect571r1"
};

QString findFile( QWidget *parent, int nType, const QString strPath );
QString saveFile( QWidget *parent, int nType, const QString strPath );

void getCKDate( const QDate date, CK_DATE *pCKDate );
QString getBool( const BIN *pBin );
QString getHexString( unsigned char *pData, int nDataLen );
void getInfoValue( const JExtensionInfo *pExtInfo, QString& strVal );

int getDataType( int nItemType );

void getBINFromString( BIN *pBin, const QString& strType, const QString& strString );
void getBINFromString( BIN *pBin, int nType, const QString& strString );
QString getStringFromBIN( const BIN *pBin, const QString& strType, bool bSeenOnly = false );
QString getStringFromBIN( const BIN *pBin, int nType, bool bSeenOnly = false );


QString getMechFlagString( unsigned long uFlag );
QString getSlotFlagString( unsigned long uFlag );
QString getTokenFlagString( unsigned long uFlag );
QString getSessionFlagString( unsigned long uFlag );
QString getSessionStateString( unsigned long uState );


#endif // COMMON_H
