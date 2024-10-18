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

#define ACT_FILE_NEW                    0x00000001
#define ACT_FILE_OPEN                   0x00000002
#define ACT_FILE_UNLOAD                 0x00000004
#define ACT_FILE_SHOW_DOCK              0x00000008
#define ACT_FILE_QUIT                   0x00000010

#define ACT_MODULE_INIT                 0x00000001
#define ACT_MODULE_FINAL                0x00000002
#define ACT_MODULE_OPEN_SESS            0x00000004
#define ACT_MODULE_CLOSE_SESS           0x00000008
#define ACT_MODULE_CLOSE_ALL            0x00000010
#define ACT_MODULE_LOGIN                0x00000020
#define ACT_MODULE_LOGOUT               0x00000040

#define ACT_OBJECT_GEN_KEYPAIR          0x00000001
#define ACT_OBJECT_GEN_KEY              0x00000002
#define ACT_OBJECT_CREATE_DATA          0x00000004
#define ACT_OBJETT_CREATE_RSA_PUB_KEY   0x00000008
#define ACT_OBJECT_CREATE_RSA_PRI_KEY   0x00000010
#define ACT_OBJECT_CREATE_EC_PUB_KEY    0x00000020
#define ACT_OBJECT_CREATE_EC_PRI_KEY    0x00000040
#define ACT_OBJECT_CREATE_ED_PUB_KEY    0x00000080
#define ACT_OBJECT_CREATE_ED_PRI_KEY    0x00000100
#define ACT_OBJECT_CREATE_DSA_PUB_KEY   0x00000200
#define ACT_OBJECT_CREATE_DSA_PRI_KEY   0x00000400
#define ACT_OBJECT_CREATE_KEY           0x00000800
#define ACT_OBJECT_DEL_OBJECT           0x00001000
#define ACT_OBJECT_EDIT_ATT             0x00002000
#define ACT_OBJECT_EDIT_ATT_LIST        0x00004000
#define ACT_OBJECT_COPY_OBJECT          0x00008000
#define ACT_OBJECT_FIND_OBJECT          0x00010000

#define ACT_CRYPT_RAND                  0x00000001
#define ACT_CRYPT_DIGEST                0x00000002
#define ACT_CRYPT_SIGN                  0x00000004
#define ACT_CRYPT_VERIFY                0x00000008
#define ACT_CRYPT_ENC                   0x00000010
#define ACT_CRYPT_DEC                   0x00000020

#define ACT_IMPORT_CERT                 0x00000001
#define ACT_IMPORT_PFX                  0x00000002
#define ACT_IMPORT_PRI_KEY              0x00000004

#define ACT_TOOL_INIT_TOKEN             0x00000001
#define ACT_TOOL_OPER_STATE             0x00000002
#define ACT_TOOL_SET_PIN                0x00000004
#define ACT_TOOL_INIT_PIN               0x00000008
#define ACT_TOOL_WRAP_KEY               0x00000010
#define ACT_TOOL_UNWRAP_KEY             0x00000020
#define ACT_TOOL_DERIVE_KEY             0x00000040
#define ACT_TOOL_TYPE_NAME              0x00000080

#define ACT_HELP_CLEAR_LOG              0x00000001
#define ACT_HELP_HALT_LOG               0x00000002
#define ACT_HELP_SETTING                0x00000004
#define ACT_HELP_LCN_INFO               0x00000008
#define ACT_HELP_BUG_ISSUE              0x00000010
#define ACT_HELP_QNA                    0x00000020
#define ACT_HELP_ABOUT                  0x00000040

static const int kFileDefault = ACT_FILE_NEW | ACT_FILE_OPEN;

static const int kModuleDefault = ACT_MODULE_INIT | ACT_MODULE_FINAL | ACT_MODULE_OPEN_SESS | ACT_MODULE_CLOSE_SESS \
                                | ACT_MODULE_LOGIN | ACT_MODULE_LOGOUT;

static const int kObjectDefault = ACT_OBJECT_GEN_KEYPAIR | ACT_OBJECT_GEN_KEY | ACT_OBJECT_CREATE_DATA \
                                | ACT_OBJECT_CREATE_KEY | ACT_OBJECT_FIND_OBJECT;

static const int kCryptDefault = ACT_CRYPT_RAND | ACT_CRYPT_DIGEST | ACT_CRYPT_SIGN | ACT_CRYPT_VERIFY \
                                 | ACT_CRYPT_ENC | ACT_CRYPT_DEC;

static const int kImportDefault = 0;

static const int kToolDefault = ACT_TOOL_OPER_STATE | ACT_TOOL_TYPE_NAME;

static const int kHelpDefault = ACT_HELP_CLEAR_LOG | ACT_HELP_HALT_LOG | ACT_HELP_ABOUT;

const QString GetSystemID();

QString findFile( QWidget *parent, int nType, const QString strPath );
QString saveFile( QWidget *parent, int nType, const QString strPath );

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
