#include <QElapsedTimer>

#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "man_applet.h"
#include "common.h"

CryptokiAPI::CryptokiAPI()
{
    p11_ctx_ = NULL;
}

void CryptokiAPI::setCTX( JP11_CTX *pCTX )
{
    if( p11_ctx_ )
    {
        JS_PKCS11_ReleaseLibrry( &p11_ctx_ );
    }

    p11_ctx_ = pCTX;
}


int CryptokiAPI::initialize( void *pReserved )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_Initialize( pReserved );
    ms = timer.elapsed();

    strIn.sprintf( "pReserved = %p", pReserved );
    manApplet->dlog( strIn );

    logResult( "C_Initialize", rv, ms );

    return rv;
}

int CryptokiAPI::finalize( void *pReserved )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_Finalize( pReserved );
    ms = timer.elapsed();

    strIn.sprintf( "pReserved = %p", pReserved );
    manApplet->dlog( strIn );

    logResult( "C_Finalize", rv, ms );

    return rv;
}

void CryptokiAPI::logResult( const QString strName, int rv, qint64 ms )
{
    QString strLog;
    QString strElapsed;

    if( ms >= 0 )
        strElapsed = QString( "[elapsed time:%1 ms]").arg(ms);

    if( rv == CKR_OK )
    {
        strLog = QString( "%1 ok%2" ).arg(strName ).arg(strElapsed);
        manApplet->log( strLog );
    }
    else
    {
        strLog = QString( "%1 error[%2:%3]%4" ).arg( strName ).arg(rv).arg( JS_PKCS11_GetErrorMsg(rv)).arg(strElapsed);
        manApplet->elog( strLog );
    }
}

void CryptokiAPI::logTemplate( const CK_ATTRIBUTE sTemplate[], int nCount )
{
    if( nCount <= 0 ) manApplet->dlog( "Template is empty" );

    for( int i = 0; i < nCount; i++ )
    {
        QString strLog = QString( "%1 Type : %2 %3")
                .arg(i).arg(sTemplate[i].type)
                .arg(JS_PKCS11_GetCKAName(sTemplate[i].type));

        manApplet->dlog( strLog );

        strLog = QString( "%1 Value[%2] : %3" )
                .arg(i).arg(sTemplate[i].ulValueLen)
                .arg( getHexString((unsigned char *)sTemplate[i].pValue, sTemplate[i].ulValueLen));

        manApplet->dlog( strLog );
    }
}
