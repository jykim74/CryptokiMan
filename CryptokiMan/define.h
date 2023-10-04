#ifndef DEFINE_H
#define DEFINE_H

#include <QStringList>

static const QString kCertificate = "Certificate";
static const QString kPublicKey = "PublicKey";
static const QString kPrivateKey = "PrivateKey";
static const QString kSecretKey = "SecretKey";
static const QString kData = "Data";

static QStringList kObjectTypeList = {
    kCertificate, kPublicKey, kPrivateKey, kSecretKey, kData
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
    "CKA_TOKEN", "CKA_PRIVATE", "CKA_MODIFIABLE",
    "CKA_LABEL", "CKA_COPYABLE", "CKA_DESTROYABLE"
};

static QStringList kDataAttList = {
    "CKA_APPLICATION", "CKA_OBJECT_ID", "CKA_VALUE"
};

static QStringList kCommonCertAttList = {
    "CKA_CERTIFICATE_TYPE", "CKA_TRUSTED", "CKA_CERTIFICATE_CATEGORY",
    "CKA_CHECK_VALUE", "CKA_START_DATE", "CKA_END_DATE",
    "CKA_PUBLIC_KEY_INFO"
};

static QStringList kX509CertAttList = {
    "CKA_SUBJECT", "CKA_ID", "CKA_ISSUER",
    "CKA_SERIAL_NUMBER", "CKA_VALUE", "CKA_URL",
    "CKA_HASH_OF_SUBJECT_PUBLIC_KEY", "CKA_HASH_OF_ISSUER_PUBLIC_KEY", "CKA_JAVA_MIDP_SECURITY_DOMAIN",
    "CKA_NAME_HASH_ALGORITHM"
};

static QStringList kCommonKeyAttList = {
    "CKA_KEY_TYPE", "CKA_ID", "CKA_START_DATE",
    "CKA_END_DATE", "CKA_DERIVE", "CKA_LOCAL",
    "CKA_KEY_GEN_MECHANISM", "CKA_ALLOWED_MECHANISMS"
};

static QStringList kPubKeyAttList = {
    "CKA_SUBJECT", "CKA_ENCRYPT", "CKA_VERIFY",
    "CKA_VERIFY_RECOVER", "CKA_WRAP", "CKA_TRUSTED",
    "CKA_WRAP_TEMPLATE", "CKA_PUBLIC_KEY_INFO"
};

static QStringList kPriKeyAttList = {
    "CKA_SUBJECT", "CKA_SENSITIVE", "CKA_DECRYPT",
    "CKA_SIGN", "CKA_SIGN_RECOVER", "CKA_UNWRAP",
    "CKA_EXTRACTABLE", "CKA_ALWAYS_SENSITIVE", "CKA_NEVER_EXTRACTABLE",
    "CKA_WRAP_WITH_TRUSTED", "CKA_UNWRAP_TEMPLATE", "CKA_ALWAYS_AUTHENTICATE",
    "CKA_PUBLIC_KEY_INFO"
};

static QStringList kSecretKeyAttList = {
    "CKA_SENSITIVE", "CKA_ENCRYPT", "CKA_DECRYPT",
    "CKA_SIGN", "CKA_VERIFY", "CKA_WRAP",
    "CKA_UNWRAP", "CKA_EXTRACTABLE", "CKA_ALWAYS_SENSITIVE",
    "CKA_NEVER_EXTRACTABLE", "CKA_CHECK_VALUE", "CKA_WRAP_WITH_TRUSTED",
    "CKA_TRUSTED", "CKA_WRAP_TEMPLATE", "CKA_UNWRAP_TEMPLATE"
};

static QStringList kRSAKeyAttList = {
    "CKA_MODULUS", "CKA_PUBLIC_EXPONENT", "CKA_PRIVATE_EXPONENT",
    "CKA_PRIME_1", "CKA_PRIME_2", "CKA_EXPONENT_1",
    "CKA_EXPONENT_2", "CKA_COEFFICIENT"
};

static QStringList kECCKeyAttList = {
    "CKA_EC_PARAMS", "CKA_EC_POINT", "CKA_VALUE"
};

static QStringList kDSAKeyAttList = {
    "CKA_PRIME", "CKA_SUBPRIME", "CKA_BASE",
    "CKA_VALUE"
};

static QStringList kDHKeyAttList = {
    "CKA_PRIME", "CKA_BASE", "CKA_VALUE"
};

static QStringList kSecretValueAttList = {
    "CKA_VALUE", "CKA_VALUE_LEN"
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

static QStringList kRSAOptionList = { "1024", "2048", "3072", "4096" };
static QStringList kDSAOptionList = { "1024", "2048", "3072", "4096" };

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
    "CKM_ECDSA", "CKM_ECDSA_SHA1", "CKM_ECDSA_SHA256", "CKM_ECDSA_SHA384", "CKM_ECDSA_SHA512",
    "CKM_DSA", "CKM_DSA_SHA1", "CKM_DSA_SHA224", "CKM_DSA_SHA256", "CKM_DSA_SHA384", "CKM_DSA_SHA512"
};

static QStringList kMechSignAsymNoLicenseList = {
    "CKM_RSA_PKCS", "CKM_SHA1_RSA_PKCS", "CKM_SHA256_RSA_PKCS", "CKM_SHA384_RSA_PKCS", "CKM_SHA512_RSA_PKCS",
    "CKM_SHA1_RSA_PKCS_PSS", "CKM_SHA256_RSA_PKCS_PSS", "CKM_SHA384_RSA_PKCS_PSS", "CKM_SHA512_RSA_PKCS_PSS",
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

static QStringList kMechGenKeyPairListNoLicense = {
  "CKM_RSA_PKCS_KEY_PAIR_GEN"
};

static QStringList kMechGenListNoLicense = {
    "CKM_AES_KEY_GEN", "CKM_GENERIC_SECRET_KEY_GEN"
};

static QStringList kDataTypeList = { "String", "Hex", "Base64" };
static QStringList kDNTypeList = { "Text", "DER" };

#endif // DEFINE_H
