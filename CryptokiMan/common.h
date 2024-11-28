/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef COMMON_H
#define COMMON_H

#include <QStringList>
#include <QWidget>
#include "js_pkcs11.h"
#include "js_pki_ext.h"
#include "define.h"

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


static CK_BBOOL kTrue = CK_TRUE;
static CK_BBOOL kFalse = CK_FALSE;
static int kNameWidth = -30;

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

enum ViewType {
    VIEW_FILE = 1,
    VIEW_MODULE,
    VIEW_OBJECT,
    VIEW_CRYPT,
    VIEW_IMPORT,
    VIEW_TOOL,
    VIEW_HELP
};

#define VIEW_FILE                       0x01000000
#define VIEW_MODULE                     0x02000000
#define VIEW_OBJECT                     0x03000000
#define VIEW_CRYPT                      0x04000000
#define VIEW_IMPORT                     0x05000000
#define VIEW_TOOL                       0x06000000
#define VIEW_HELP                       0x07000000

#define ACT_FILE_NEW                    VIEW_FILE | 0x00000001
#define ACT_FILE_OPEN                   VIEW_FILE | 0x00000002
#define ACT_FILE_UNLOAD                 VIEW_FILE | 0x00000004
#define ACT_FILE_SHOW_DOCK              VIEW_FILE | 0x00000008
#define ACT_FILE_QUIT                   VIEW_FILE | 0x00000010

#define ACT_MODULE_INIT                 VIEW_MODULE | 0x00000001
#define ACT_MODULE_FINAL                VIEW_MODULE | 0x00000002
#define ACT_MODULE_OPEN_SESS            VIEW_MODULE | 0x00000004
#define ACT_MODULE_CLOSE_SESS           VIEW_MODULE | 0x00000008
#define ACT_MODULE_CLOSE_ALL            VIEW_MODULE | 0x00000010
#define ACT_MODULE_LOGIN                VIEW_MODULE | 0x00000020
#define ACT_MODULE_LOGOUT               VIEW_MODULE | 0x00000040

#define ACT_OBJECT_GEN_KEYPAIR          VIEW_OBJECT | 0x00000001
#define ACT_OBJECT_GEN_KEY              VIEW_OBJECT | 0x00000002
#define ACT_OBJECT_CREATE_DATA          VIEW_OBJECT | 0x00000004
#define ACT_OBJECT_CREATE_RSA_PUB_KEY   VIEW_OBJECT | 0x00000008
#define ACT_OBJECT_CREATE_RSA_PRI_KEY   VIEW_OBJECT | 0x00000010
#define ACT_OBJECT_CREATE_EC_PUB_KEY    VIEW_OBJECT | 0x00000020
#define ACT_OBJECT_CREATE_EC_PRI_KEY    VIEW_OBJECT | 0x00000040
#define ACT_OBJECT_CREATE_ED_PUB_KEY    VIEW_OBJECT | 0x00000080
#define ACT_OBJECT_CREATE_ED_PRI_KEY    VIEW_OBJECT | 0x00000100
#define ACT_OBJECT_CREATE_DSA_PUB_KEY   VIEW_OBJECT | 0x00000200
#define ACT_OBJECT_CREATE_DSA_PRI_KEY   VIEW_OBJECT | 0x00000400
#define ACT_OBJECT_CREATE_KEY           VIEW_OBJECT | 0x00000800
#define ACT_OBJECT_DEL_OBJECT           VIEW_OBJECT | 0x00001000
#define ACT_OBJECT_EDIT_ATT             VIEW_OBJECT | 0x00002000
#define ACT_OBJECT_EDIT_ATT_LIST        VIEW_OBJECT | 0x00004000
#define ACT_OBJECT_COPY_OBJECT          VIEW_OBJECT | 0x00008000
#define ACT_OBJECT_FIND_OBJECT          VIEW_OBJECT | 0x00010000

#define ACT_CRYPT_RAND                  VIEW_CRYPT | 0x00000001
#define ACT_CRYPT_DIGEST                VIEW_CRYPT | 0x00000002
#define ACT_CRYPT_SIGN                  VIEW_CRYPT | 0x00000004
#define ACT_CRYPT_VERIFY                VIEW_CRYPT | 0x00000008
#define ACT_CRYPT_ENC                   VIEW_CRYPT | 0x00000010
#define ACT_CRYPT_DEC                   VIEW_CRYPT | 0x00000020
#define ACT_CRYPT_HSM_MAN               VIEW_CRYPT | 0x00000040

#define ACT_IMPORT_CERT                 VIEW_IMPORT | 0x00000001
#define ACT_IMPORT_PFX                  VIEW_IMPORT | 0x00000002
#define ACT_IMPORT_PRI_KEY              VIEW_IMPORT | 0x00000004

#define ACT_TOOL_INIT_TOKEN             VIEW_TOOL | 0x00000001
#define ACT_TOOL_OPER_STATE             VIEW_TOOL | 0x00000002
#define ACT_TOOL_SET_PIN                VIEW_TOOL | 0x00000004
#define ACT_TOOL_INIT_PIN               VIEW_TOOL | 0x00000008
#define ACT_TOOL_WRAP_KEY               VIEW_TOOL | 0x00000010
#define ACT_TOOL_UNWRAP_KEY             VIEW_TOOL | 0x00000020
#define ACT_TOOL_DERIVE_KEY             VIEW_TOOL | 0x00000040
#define ACT_TOOL_TYPE_NAME              VIEW_TOOL | 0x00000080
#define ACT_TOOL_MAKE_CSR               VIEW_TOOL | 0x00000100

#define ACT_HELP_CLEAR_LOG              VIEW_HELP | 0x00000001
#define ACT_HELP_HALT_LOG               VIEW_HELP | 0x00000002
#define ACT_HELP_SETTING                VIEW_HELP | 0x00000004
#define ACT_HELP_LCN_INFO               VIEW_HELP | 0x00000008
#define ACT_HELP_BUG_ISSUE              VIEW_HELP | 0x00000010
#define ACT_HELP_QNA                    VIEW_HELP | 0x00000020
#define ACT_HELP_ABOUT                  VIEW_HELP | 0x00000040

static const int kFileDefault = ACT_FILE_NEW | ACT_FILE_OPEN;

static const int kModuleDefault = ACT_MODULE_INIT | ACT_MODULE_OPEN_SESS | ACT_MODULE_CLOSE_SESS \
                                | ACT_MODULE_LOGIN | ACT_MODULE_LOGOUT;

static const int kObjectDefault = ACT_OBJECT_GEN_KEYPAIR | ACT_OBJECT_GEN_KEY | ACT_OBJECT_CREATE_DATA \
                                | ACT_OBJECT_CREATE_KEY | ACT_OBJECT_FIND_OBJECT;

static const int kCryptDefault = ACT_CRYPT_RAND | ACT_CRYPT_DIGEST | ACT_CRYPT_SIGN | ACT_CRYPT_VERIFY \
                                 | ACT_CRYPT_ENC | ACT_CRYPT_DEC | ACT_CRYPT_HSM_MAN;

static const int kImportDefault = 0;

static const int kToolDefault = ACT_TOOL_TYPE_NAME;

static const int kHelpDefault = ACT_HELP_CLEAR_LOG | ACT_HELP_HALT_LOG | ACT_HELP_ABOUT;

const QString GetSystemID();

QString findFile( QWidget *parent, int nType, const QString strPath );
QString findFile( QWidget *parent, int nType, const QString strPath, QString& strSelected );
QString findSaveFile( QWidget *parent, int nType, const QString strPath );
QString findFolder( QWidget *parent, const QString strPath );

void getQDateToCKDate( const QDate date, CK_DATE *pCKDate );
void getCKDateToQDate( const CK_DATE *pCKDate, QDate *pQDate );
QString getBool( const BIN *pBin );
QString getHexString( const BIN *pBin );
QString getHexString( unsigned char *pData, int nDataLen );

const QString getHexStringArea( unsigned char *pData, int nDataLen, int nWidth = -1 );
const QString getHexStringArea( const BIN *pData, int nWidth = -1 );
const QString getHexStringArea( const QString strMsg, int nWidth = -1);

void getInfoValue( const JExtensionInfo *pExtInfo, QString& strVal );

int getDataType( int nItemType );
int getDataLen( int nType, const QString strData );
int getDataLen( const QString strType, const QString strData );
const QString getDataLenString( int nType, const QString strData );
const QString getDataLenString( const QString strType, const QString strData );


void getBINFromString( BIN *pBin, const QString& strType, const QString& strString );
void getBINFromString( BIN *pBin, int nType, const QString& strString );
QString getStringFromBIN( const BIN *pBin, const QString& strType, bool bSeenOnly = false );
QString getStringFromBIN( const BIN *pBin, int nType, bool bSeenOnly = false );

QString getMechFlagString( unsigned long uFlag );
QString getSlotFlagString( unsigned long uFlag );
QString getTokenFlagString( unsigned long uFlag );
QString getSessionFlagString( unsigned long uFlag );
QString getSessionStateString( unsigned long uState );

const QString getItemTypeName( int nType );

bool isValidNumFormat( const QString strInput, int nNumber );
bool isEmail( const QString strEmail );
bool isHex( const QString strHexString );
bool isBase64( const QString strBase64String );
bool isURLEncode( const QString strURLEncode );


#endif // COMMON_H
