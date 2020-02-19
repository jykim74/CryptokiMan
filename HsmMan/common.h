#ifndef COMMON_H
#define COMMON_H

#include <QStringList>

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

#endif // COMMON_H
