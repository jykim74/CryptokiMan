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

CK_SESSION_HANDLE CryptokiAPI::getSessionHandle()
{
    if( p11_ctx_ == NULL ) return -1;

    return p11_ctx_->hSession;
}

int CryptokiAPI::Initialize( void *pReserved )
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

int CryptokiAPI::Finalize( void *pReserved )
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

int CryptokiAPI::GetSlotList( CK_BBOOL bVal, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pSlotCnt )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetSlotList( bVal, pSlotList, pSlotCnt );
    ms = timer.elapsed();

    strIn.sprintf( "token_present = %02x slot_id = %p slot_count = %p", bVal, pSlotList, pSlotCnt );
    manApplet->dlog( strIn );

    logResult( "C_GetSlotList", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString("SlotCount = %1").arg( *pSlotCnt ));
    }

    return 0;
}

int CryptokiAPI::GetSlotList2( CK_BBOOL bVal, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pSlotCnt )
{
    int rv  = 0;

    rv = GetSlotList( bVal, NULL, pSlotCnt );
    if( rv != CKR_OK ) return rv;

    if( *pSlotCnt > MAX_SLOT_COUNT )
    {
        return -1;
    }

    rv = GetSlotList( bVal, pSlotList, pSlotCnt );


    return rv;
}

int CryptokiAPI::GetInfo( CK_INFO_PTR pInfo )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    strIn.sprintf( "INFO_PTR = %p", pInfo );

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetInfo( pInfo );
    ms = timer.elapsed();

    manApplet->dlog( strIn );

    logResult( "C_GetInfo", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::GetSlotInfo( CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pSlotInfo )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetSlotInfo( slotID, pSlotInfo );
    ms = timer.elapsed();

    strIn.sprintf( "SLOT_ID = %d", slotID );
    manApplet->dlog( strIn );
    strIn.sprintf( "SLOT_INFO = %p", pSlotInfo );
    manApplet->dlog( strIn );

    logResult( "C_GetSlotInfo", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::GetTokenInfo( CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pTokenInfo )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetTokenInfo( slotID, pTokenInfo );
    ms = timer.elapsed();

    strIn.sprintf( "SLOT_ID = %d", slotID );
    manApplet->dlog( strIn );
    strIn.sprintf( "TOKEN_INFO = %p", pTokenInfo );
    manApplet->dlog( strIn );

    logResult( "C_GetTokenInfo", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::GetMechanismList( CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechList, CK_ULONG *puMechCount )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetMechanismList( slotID, pMechList, puMechCount );
    ms = timer.elapsed();

    strIn.sprintf( "SLOT_ID = %d", slotID );
    manApplet->dlog( strIn );
    strIn.sprintf( "MECHANISM_TYPE_PTR = %p", pMechList );
    manApplet->dlog( strIn );
    strIn.sprintf( "MECHANISM_COUNT_PTR = %p", puMechCount );

    logResult( "C_GetMechanismList", rv, ms );
    manApplet->dlog( strIn );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::GetMechanismInfo( CK_SLOT_ID slotID, CK_MECHANISM_TYPE iMechType, CK_MECHANISM_INFO_PTR pInfo )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetMechanismInfo( slotID, iMechType, pInfo );
    ms = timer.elapsed();

    strIn.sprintf( "SLOT_ID = %d", slotID );
    manApplet->dlog( strIn );
    strIn.sprintf( "MECHANISM_TYPE = %d", iMechType );
    manApplet->dlog( strIn );
    strIn.sprintf( "MECHAINSM_INFO_PTR = %p", pInfo );
    manApplet->dlog( strIn );

    logResult( "C_GetMechanismInfo", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::GetSessionInfo( CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pSessionInfo )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetSessionInfo( hSession, pSessionInfo );
    ms = timer.elapsed();

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );
    strIn.sprintf( "SESSION_INFO_PTR = %p", pSessionInfo );
    manApplet->dlog( strIn );

    logResult( "C_GetSessionInfo", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::FindObjectsInit( CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG uCount )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_FindObjectsInit( hSession, pTemplate, uCount );
    ms = timer.elapsed();

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );
    strIn.sprintf( "ATTRIBUTE_PTR = %p", pTemplate );
    manApplet->dlog( strIn );
    strIn.sprintf( "ATTRIBUTE_COUNT = %d", uCount );
    manApplet->dlog( strIn );

    logTemplate( pTemplate, uCount );

    logResult( "C_FindObjectsInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::FindObjects( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG uMaxObjCount, CK_ULONG_PTR puObjCount )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_FindObjects( hSession, phObject, uMaxObjCount, puObjCount );
    ms = timer.elapsed();

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );
    strIn.sprintf( "OBJECT_HANDLE_PTR = %p", phObject );
    manApplet->dlog( strIn );
    strIn.sprintf( "MAX_OBJECT_COUNT = %d", uMaxObjCount );
    manApplet->dlog( strIn );
    strIn.sprintf( "OBJECT_COUNT_PTR = %p", puObjCount );
    manApplet->dlog( strIn );

    logResult( "C_FindObjects", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::FindObjectsFinal( CK_SESSION_HANDLE hSession )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_FindObjectsFinal( hSession );
    ms = timer.elapsed();

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    logResult( "C_FindObjectsFinal", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::GetObjectSize( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR puSize )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetObjectSize( hSession, hObject, puSize );
    ms = timer.elapsed();

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDLE = %ud", hObject );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_SIZE_PTR = %p", puSize );
    manApplet->dlog( strIn );

    logResult( "C_GetObjectSize", rv, ms );

    if( rv == CKR_OK )
    {

    }

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
