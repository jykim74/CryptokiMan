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

/*
#define     HM_ITEM_TYPE_CERTIFICATE_OBJECT 11
#define     HM_ITEM_TYPE_PUBLICKEY_OBJECT   12
#define     HM_ITEM_TYPE_PRIVATEKEY_OBJECT  13
#define     HM_ITEM_TYPE_SECRETKEY_OBJECT   14
#define     HM_ITEM_TYPE_DATA_OBJECT        15
*/

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
