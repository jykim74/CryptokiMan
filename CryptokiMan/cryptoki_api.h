#ifndef CRYPTOKIAPI_H
#define CRYPTOKIAPI_H

#include <QObject>
#include <QString>
#include "js_pkcs11.h"


class CryptokiAPI : public QObject
{
    Q_OBJECT

public:
    CryptokiAPI();
    void setCTX( JP11_CTX *pCTX );

    int initialize( void *pReserved );
    int finalize( void *pReserved );

private:
    void logResult( const QString strName, int rv, qint64 ms = -1 );
    void logTemplate( const CK_ATTRIBUTE sTemplate[], int nCount );

private:
    JP11_CTX       *p11_ctx_;
};

#endif // CRYPTOKIAPI_H
