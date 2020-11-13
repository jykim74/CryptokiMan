#ifndef COMMON_H
#define COMMON_H

#include <QStringList>
#include <QWidget>

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

#endif // COMMON_H
