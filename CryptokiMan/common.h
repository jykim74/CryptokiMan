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

QString findFile( QWidget *parent, int nType, const QString strPath );
void getCKDate( const QDate date, CK_DATE *pCKDate );
QString getBool( const BIN *pBin );
QString getHexString( unsigned char *pData, int nDataLen );

#endif // COMMON_H
