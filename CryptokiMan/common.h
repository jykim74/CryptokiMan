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
       JS_FILE_TYPE_PFX,
       JS_FILE_TYPE_ALL };

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
    "CKA_VALUE", "CKA_BASE", "CKA_PRIME", "CKA_SUBPRIME"
};

static QStringList kPriKetAttList = {
    "CKA_SUBJECT", "CKA_MODULUS", "CKA_PUBLIC_EXPONENT", "CKA_PRIVATE_EXPONENT",
    "CKA_PRIME_1", "CKA_PRIME_2", "CKA_EXPONENT_1", "CKA_EXPONENT_2",
    "CKA_ECDSA_PARAMS", "CKA_VALUE", "CKA_SENSITIVE", "CKA_UNWARP",
    "CKA_SIGN", "CKA_DECRYPT", "CKA_DERIVE", "CKA_EXTRACTABLE",
    "CKA_START_DATE", "CKA_END_DATE", "CKA_VALUE"
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

static QStringList kMechDigestList = {
    "CKM_MD5", "CKM_SHA_1", "CKM_SHA256", "CKM_SHA512"
};

static QStringList kMechEncSymList = {
    "CKM_DES3_ECB", "CKM_DES3_CBC", "CKM_DES3_CBC_PAD",
    "CKM_AES_ECB", "CKM_AES_CBC","CKM_AES_CBC_PAD", "CKM_AES_CTR", "CKM_AES_GCM"
};

static QStringList kMechEncAsymList = {
    "CKM_RSA_PKCS"
};

static QStringList kMechSignAsymList = {
    "CKM_RSA_PKCS", "CKM_SHA1_RSA_PKCS", "CKM_SHA256_RSA_PKCS", "CKM_SHA384_RSA_PKCS", "CKM_SHA512_RSA_PKCS",
    "CKM_SHA1_RSA_PKCS_PSS", "CKM_SHA256_RSA_PKCS_PSS", "CKM_SHA384_RSA_PKCS_PSS", "CKM_SHA512_RSA_PKCS_PSS",
    "CKM_ECDSA", "CKM_ECDSA_SHA1", "CKM_ECDSA_SHA256", "CKM_ECDSA_SHA384", "CKM_ECDSA_SHA512"
};

static QStringList kMechSignSymList = {
    "CKM_MD5_HMAC", "CKM_SHA_1_HMAC", "CKM_SHA256_HMAC", "CKM_SHA384_HMAC", "CKM_SHA512_HMAC"
};

static QStringList kMechWrapSymList = {
    "CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_PAD"
};

static QStringList kMechWrapAsymList = {
    "CKM_RSA_PKCS", "CKM_RSA_PKCS_OAEP",
};

static QStringList kMechDeriveList = {
    "CKM_DH_PKCS_DERIVE", "CKM_ECDH1_DERIVE",
    "CKM_DES_ECB_ENCRYPT_DATA", "CKM_DES_CBC_ENCRYPT_DATA", "CKM_DES3_ECB_ENCRYPT_DATA", "CKM_DES3_CBC_ENCRYPT_DATA",
    "CKM_AES_ECB_ENCRYPT_DATA", "CKM_AES_CBC_ENCRYPT_DATA", "CKM_CONCATENATE_DATA_AND_BASE",
    "CKM_CONCATENATE_BASE_AND_DATA", "CKM_CONCATENATE_BASE_AND_KEY",
    "CKM_SHA1_KEY_DERIVATION", "CKM_SHA256_KEY_DERIVATION", "CKM_SHA384_KEY_DERIVATION", "CKM_SHA512_KEY_DERIVATION",
    "CKM_SHA224_KEY_DERIVATION"
};

static QStringList kMechGenKeyPairList = {
  "CKM_RSA_PKCS_KEY_PAIR_GEN", "CKM_ECDSA_KEY_PAIR_GEN", "CKM_DH_PKCS_KEY_PAIR_GEN"
};

static QStringList kMechGenList = {
    "CKM_AES_KEY_GEN", "CKM_DES_KEY_GEN", "CKM_DES3_KEY_GEN", "CKM_GENERIC_SECRET_KEY_GEN"
};

static QStringList kDataTypeList = { "String", "Hex", "Base64" };

QString findFile( QWidget *parent, int nType, const QString strPath );
QString saveFile( QWidget *parent, int nType, const QString strPath );

void getCKDate( const QDate date, CK_DATE *pCKDate );
QString getBool( const BIN *pBin );
QString getHexString( unsigned char *pData, int nDataLen );
void getInfoValue( const JExtensionInfo *pExtInfo, QString& strVal );

int getDataType( int nItemType );
int getDataLen( int nType, const QString strData );
int getDataLen( const QString strType, const QString strData );

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
