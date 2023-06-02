#include <QElapsedTimer>

#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "man_applet.h"
#include "common.h"

CryptokiAPI::CryptokiAPI()
{
    p11_ctx_ = NULL;
    init_ = false;
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

int CryptokiAPI::openLibrary( const QString strPath )
{
    int ret = 0;

    ret = JS_PKCS11_LoadLibrary( (JP11_CTX **)&p11_ctx_, strPath.toLocal8Bit().toStdString().c_str() );

    return ret;
}

int CryptokiAPI::unloadLibrary()
{
    if( p11_ctx_ ) JS_PKCS11_ReleaseLibrry( (JP11_CTX **)&p11_ctx_ );
    manApplet->log( "library is released" );
    return 0;
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

    strIn.sprintf( "C_Initialize( pReserved = @%p )", pReserved );
    manApplet->dlog( strIn );

    logResult( "C_Initialize", rv, ms );
    if( rv == CKR_OK ) init_ = true;

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

    strIn.sprintf( "C_Finalize( pReserved = @%p )", pReserved );
    manApplet->dlog( strIn );

    logResult( "C_Finalize", rv, ms );
    if( rv == CKR_OK ) init_ = false;

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

    strIn.sprintf( "C_GetSlotList( token_present = %d, slot_id = @%p, slot_count = @%p )", bVal, pSlotList, pSlotCnt );
    manApplet->dlog( strIn );

    logResult( "C_GetSlotList", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString("SlotCount = %1").arg( *pSlotCnt ));

        if( pSlotList )
        {
            for( int i = 0; i < *pSlotCnt; i++ )
            {
                manApplet->dlog( QString( "Slot : %1").arg( pSlotList[i] ));
            }
        }
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

    strIn.sprintf( "C_GetInfo( INFO_PTR = @%p )", pInfo );

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetInfo( pInfo );
    ms = timer.elapsed();

    manApplet->dlog( strIn );

    logResult( "C_GetInfo", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString("cryptoki_version : major %1 minor %2").arg( pInfo->cryptokiVersion.major ).arg( pInfo->cryptokiVersion.minor ));
        manApplet->dlog( QString("manufacturer_id  : %1").arg( getHexString( pInfo->manufacturerID, sizeof(pInfo->manufacturerID ))));
        manApplet->dlog( QString("flags            : %1").arg( pInfo->flags ));
        manApplet->dlog( QString("library_version  : major %1 minor %2").arg( pInfo->libraryVersion.major).arg( pInfo->libraryVersion.minor ));
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

    strIn.sprintf( "C_GetSlotInfo( SLOT_ID = %d, SLOT_INFO = @%p )", slotID, pSlotInfo );
    manApplet->dlog( strIn );

    logResult( "C_GetSlotInfo", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "slot_description : %1").arg( getHexString( pSlotInfo->slotDescription, sizeof( pSlotInfo->slotDescription ))));
        manApplet->dlog( QString( "manufacturer_id  : %1").arg( getHexString(pSlotInfo->manufacturerID, sizeof(pSlotInfo->manufacturerID))));
        manApplet->dlog( QString( "flags            : %1 - %2").arg( pSlotInfo->flags ).arg( getSlotFlagString( pSlotInfo->flags)));
        manApplet->dlog( QString( "hardware version : major %1 minor %2").arg( pSlotInfo->hardwareVersion.major).arg( pSlotInfo->hardwareVersion.minor));
        manApplet->dlog( QString( "firmware_version : major %1 minor %2").arg( pSlotInfo->firmwareVersion.major).arg( pSlotInfo->firmwareVersion.minor));
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

    strIn.sprintf( "C_GetTokenInfo( SLOT_ID = %d, TOKEN_INFO = @%p )", slotID, pTokenInfo );
    manApplet->dlog( strIn );

    logResult( "C_GetTokenInfo", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "label                : %1").arg( getHexString( pTokenInfo->label, sizeof(pTokenInfo->label ))));
        manApplet->dlog( QString( "manufacturer_id      : %1").arg( getHexString( pTokenInfo->manufacturerID, sizeof(pTokenInfo->manufacturerID))));
        manApplet->dlog( QString( "model                : %1").arg( getHexString(pTokenInfo->model, sizeof(pTokenInfo->model))));
        manApplet->dlog( QString( "serial_number        : %1").arg(getHexString( pTokenInfo->serialNumber, sizeof(pTokenInfo->serialNumber))));
        manApplet->dlog( QString( "flags                : %1 - %2").arg( pTokenInfo->flags ).arg( getTokenFlagString( pTokenInfo->flags )));
        manApplet->dlog( QString( "max_session_count    : %1 - 0x%2").arg( pTokenInfo->ulMaxSessionCount ).arg( pTokenInfo->ulMaxSessionCount, 0, 16, QLatin1Char('0')).toUpper());
        manApplet->dlog( QString( "session_count        : %1 - 0x%2").arg( pTokenInfo->ulSessionCount ).arg( pTokenInfo->ulSessionCount, 0, 16, QLatin1Char('0')).toUpper());
        manApplet->dlog( QString( "max_rw_session_count : %1 - 0x%2").arg( pTokenInfo->ulMaxRwSessionCount ).arg( pTokenInfo->ulMaxRwSessionCount, 0, 16, QLatin1Char('0')).toUpper());
        manApplet->dlog( QString( "rw_session_count     : %1 - 0x%2").arg( pTokenInfo->ulRwSessionCount).arg( pTokenInfo->ulRwSessionCount, 0, 16, QLatin1Char('0')).toUpper());
        manApplet->dlog( QString( "max_pin_len          : %1" ).arg( pTokenInfo->ulMaxPinLen));
        manApplet->dlog( QString( "min_pin_len          : %1").arg( pTokenInfo->ulMinPinLen));
        manApplet->dlog( QString( "total_public_memory  : %1 - 0x%2").arg( pTokenInfo->ulTotalPublicMemory ).arg( pTokenInfo->ulTotalPublicMemory, 0, 16, QLatin1Char('0')).toUpper());
        manApplet->dlog( QString( "free_public_memory   : %1 - 0x%2" ).arg( pTokenInfo->ulFreePublicMemory).arg( pTokenInfo->ulFreePublicMemory, 0, 16, QLatin1Char('0')).toUpper());
        manApplet->dlog( QString( "total_private_memory : %1 - 0x%2").arg( pTokenInfo->ulTotalPrivateMemory ).arg( pTokenInfo->ulTotalPrivateMemory, 0, 16, QLatin1Char('0')).toUpper());
        manApplet->dlog( QString( "free_private_memory  : %1 - 0x%2" ).arg( pTokenInfo->ulFreePrivateMemory).arg( pTokenInfo->ulFreePrivateMemory, 0, 16, QLatin1Char('0')).toUpper());
        manApplet->dlog( QString( "hardware version     : major %1 minor %2").arg( pTokenInfo->hardwareVersion.major).arg( pTokenInfo->hardwareVersion.minor));
        manApplet->dlog( QString( "firmware_version     : major %1 minor %2").arg( pTokenInfo->firmwareVersion.major).arg( pTokenInfo->firmwareVersion.minor));
        manApplet->dlog( QString( "utc_time             : %1").arg(getHexString(pTokenInfo->utcTime, sizeof(pTokenInfo->utcTime))));
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

    strIn.sprintf( "C_GetMechanismList( SLOT_ID = %d, MECHANISM_TYPE_PTR = @%p, MECHANISM_COUNT_PTR = %d )",
                   slotID, pMechList, *puMechCount );
    manApplet->dlog( strIn );

    logResult( "C_GetMechanismList", rv, ms );
    manApplet->dlog( strIn );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "Count : %1").arg( *puMechCount ));
        if( pMechList )
        {
            for( int i = 0; i < *puMechCount; i++ )
            {
                manApplet->dlog( QString( "Mechanism : %1 - %2").arg( pMechList[i]).arg(JS_PKCS11_GetCKMName( pMechList[i]) ));
            }
        }
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

    strIn.sprintf( "C_GetMechanismInfo( SLOT_ID = %d, MECHANISM_TYPE = %d, MECHAINSM_INFO_PTR = @%p )",
                   slotID, iMechType, pInfo );
    manApplet->dlog( strIn );

    logResult( QString("C_GetMechanismInfo: %1").arg( JS_PKCS11_GetCKMName(iMechType)), rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "min_key_size : %1").arg( pInfo->ulMinKeySize ));
        manApplet->dlog( QString( "max_key_size : %1").arg( pInfo->ulMaxKeySize ));
        manApplet->dlog( QString( "flags        : %1 - %2").arg( pInfo->flags ).arg( getMechFlagString( pInfo->flags )));
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

    strIn.sprintf( "C_GetSessionInfo( SESSION_HANDLE = %u, SESSION_INFO_PTR = @%p )", hSession, pSessionInfo );
    manApplet->dlog( strIn );

    logResult( "C_GetSessionInfo", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "slot_id      : %1").arg( pSessionInfo->slotID ));
        manApplet->dlog( QString( "state        : %1 - %2").arg( pSessionInfo->state ).arg( getSessionStateString( pSessionInfo->state )));
        manApplet->dlog( QString( "flags        : %1 - %2").arg( pSessionInfo->flags ).arg( getSessionFlagString( pSessionInfo->flags )));
        manApplet->dlog( QString( "device error : %1").arg( pSessionInfo->ulDeviceError ));
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

    strIn.sprintf( "C_FindObjectsInit( SESSION_HANDLE = %u, ATTRIBUTE_PTR = @%p, ATTRIBUTE_COUNT = %d )",
                   hSession, pTemplate, uCount );
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

    strIn.sprintf( "C_FindObjects( SESSION_HANDLE = %u, OBJECT_HANDLE_PTR = @%p, MAX_OBJECT_COUNT = %d, OBJECT_COUNT_PTR = @%p )",
                   hSession, phObject, uMaxObjCount, puObjCount );
    manApplet->dlog( strIn );

    logResult( "C_FindObjects", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "Object Count : %1").arg( *puObjCount));
        if( phObject )
        {
            for( int i = 0; i < *puObjCount; i++ )
            {
                manApplet->dlog( QString( "Object Handler : %1").arg( phObject[i] ));
            }
        }
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

    strIn.sprintf( "C_FindObjectsFinal( SESSION_HANDLE = %u )", hSession );
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

    strIn.sprintf( "C_GetObjectSize( SESSION_HANDLE = %u, OBJECT_HANDLE = %u, OBJECT_SIZE_PTR = @%p )",
                   hSession, hObject, puSize );
    manApplet->dlog( strIn );

    logResult( "C_GetObjectSize", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "Object Size : %1").arg( *puSize ));
    }

    return rv;
}

int CryptokiAPI::GetAttributeValue( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pAttribute, CK_ULONG uAttributeCnt )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetAttributeValue( hSession, hObject, pAttribute, uAttributeCnt );
    ms = timer.elapsed();

    strIn.sprintf( "C_GetAttributeValue( SESSION_HANDLE = %u, OBJECT_HANDLE = %u )", hSession, hObject );
    manApplet->dlog( strIn );

    logTemplate( pAttribute, uAttributeCnt );

    logResult( QString("C_GetAttributeValue[%1:%2]")
               .arg(pAttribute->type)
               .arg(JS_PKCS11_GetCKAName(pAttribute->type)), rv, ms );

    if( rv == CKR_OK )
    {
       manApplet->dlog( QString( "Attribute Value : %1").arg( getHexString( (unsigned char *)pAttribute->pValue, pAttribute->ulValueLen )));
    }

    return rv;
}

int CryptokiAPI::GetAttributeValue2( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_TYPE attrType, BIN *pBinVal )
{
    CK_RV           rv;
    CK_ATTRIBUTE    sAttribute;

    if( hSession <= 0 ) return -1;

    memset( &sAttribute, 0x00, sizeof(sAttribute));
    sAttribute.type = attrType;

    rv = GetAttributeValue( hSession, hObject, &sAttribute, 1 );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to run C_GetAttributeValue(%s:%s:%d)\n", JS_PKCS11_GetCKAName(attrType),JS_PKCS11_GetErrorMsg(rv), rv );
        return rv;
    }

    if( sAttribute.ulValueLen > 0 )
    {
        sAttribute.pValue = (CK_BYTE_PTR)JS_calloc( 1, sAttribute.ulValueLen );
        if( sAttribute.pValue == NULL )
        {
            fprintf( stderr, "out of memory\n" );
            return -1;
        }

        rv = GetAttributeValue( hSession, hObject, &sAttribute, 1 );

        if( rv != CKR_OK )
        {
            if( sAttribute.pValue ) JS_free( sAttribute.pValue );
            sAttribute.pValue = NULL;

            return rv;
        }

        JS_BIN_set( pBinVal, (unsigned char *)sAttribute.pValue, sAttribute.ulValueLen );
        JS_free( sAttribute.pValue );
    }

    return rv;
}

int CryptokiAPI::SetAttributeValue( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pAttribute, CK_ULONG uAttributeCnt )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_SetAttributeValue( hSession, hObject, pAttribute, uAttributeCnt );
    ms = timer.elapsed();

    strIn.sprintf( "C_SetAttributeValue( SESSION_HANDLE = %u, OBJECT_HANDLE = %u )", hSession, hObject );
    manApplet->dlog( strIn );

    logTemplate( pAttribute, uAttributeCnt );

    logResult( "C_SetAttributeValue", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::SetAttributeValue2( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_TYPE attrType, BIN *pBinVal )
{
    int     rv = 0;
    CK_ATTRIBUTE        sTemplate;

    if( hSession <= 0 ) return -1;

    sTemplate.type = attrType;
    sTemplate.pValue = pBinVal->pVal;
    sTemplate.ulValueLen = pBinVal->nLen;

    rv = SetAttributeValue( hSession, hObject, &sTemplate, 1 );

    return rv;
}

int CryptokiAPI::OpenSession( CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_OpenSession( slotID, flags, pApplication, Notify, phSession );
    ms = timer.elapsed();

    strIn.sprintf( "C_OpenSession( SLOT_ID = %d, FLAGS = %d, APPLICATION_PTR = @%p, NOTIFY = @%p, SESSION_HANDLE_PTR = @%p )",
                   slotID, flags, pApplication, Notify, phSession );
    manApplet->dlog( strIn );

    logResult( "C_OpenSession", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "Session Handler : %1").arg( *phSession ));
    }

    return rv;
}

int CryptokiAPI::CloseSession( CK_SESSION_HANDLE hSession )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_CloseSession( hSession );
    ms = timer.elapsed();

    strIn.sprintf( "C_CloseSession( SESSION_HANDLE = %u )", hSession );
    manApplet->dlog( strIn );

    logResult( "C_CloseSession", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::CloseAllSession( CK_SLOT_ID slotID )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_CloseAllSessions( slotID );
    ms = timer.elapsed();

    strIn.sprintf( "C_CloseAllSessions( SLOT_ID = %d )", slotID );
    manApplet->dlog( strIn );

    logResult( "C_CloseAllSessions", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::Login( CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_Login( hSession, userType, pPin, ulPinLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_Login( SESSION_HANDLE = %u, USER_TYPE = %d, Pin = %s, PinLen = %d )",
                   hSession, userType, pPin, ulPinLen );
    manApplet->dlog( strIn );

    logResult( "C_Login", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::Logout( CK_SESSION_HANDLE hSession )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_Logout( hSession );
    ms = timer.elapsed();

    strIn.sprintf( "C_Logout( SESSION_HANDLE = %u )", hSession );
    manApplet->dlog( strIn );

    logResult( "C_Logout", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::GenerateKeyPair(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_ATTRIBUTE_PTR pPubTemplate,
        CK_ULONG ulPubTemplateCnt,
        CK_ATTRIBUTE_PTR pPriTemplate,
        CK_ULONG ulPriTemplateCnt,
        CK_OBJECT_HANDLE_PTR phPubKey,
        CK_OBJECT_HANDLE_PTR phPriKey )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GenerateKeyPair( hSession, pMechanism, pPubTemplate, ulPubTemplateCnt, pPriTemplate, ulPriTemplateCnt, phPubKey, phPriKey );
    ms = timer.elapsed();

    strIn.sprintf( "C_GenerateKeyPair( SESSION_HANDLE = %u, MECHANISM_PTR = @%p, "
                   "PUBLIC_KEY_TEMPLATE_PTR = @%p PUBLIC_KEY_ATTRIBUTE_COUNT = %d, "
                   "PRIVATE_KEY_TEMPLATE_PTR = @%p PRIVATE_KEY_ATTRIBUTE_COUNT = %d, "
                   "OBJECT_HANDL_PTR = @%p, OBJECT_HANDL_PTR = @%p )",
                   hSession, pMechanism, pPubTemplate, ulPubTemplateCnt, pPriTemplate, ulPriTemplateCnt, phPubKey, phPriKey );

    manApplet->dlog( strIn );

    logTemplate( pPubTemplate, ulPubTemplateCnt );
    logTemplate( pPriTemplate, ulPriTemplateCnt );


    logResult( "C_GenerateKeyPair", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "Public Handler : %1").arg( *phPubKey ));
        manApplet->dlog( QString( "Private Handler : %1").arg( *phPriKey ));
    }

    return rv;
}

int CryptokiAPI::GenerateKey(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulTemplateCnt,
        CK_OBJECT_HANDLE_PTR phKey )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GenerateKey( hSession, pMechanism, pTemplate, ulTemplateCnt, phKey );
    ms = timer.elapsed();

    strIn.sprintf( "C_GenerateKey( SESSION_HANDLE = %u, MECHANISM_PTR = @%p, KEY_TEMPATE_PTR = @%p, KEY_ATTRIBUTE_COUNT = %d, OBJECT_HANDL_PTR = @%p )",
                   hSession, pMechanism, pTemplate, ulTemplateCnt, phKey );
    manApplet->dlog( strIn );

    logTemplate( pTemplate, ulTemplateCnt );


    logResult( "C_GenerateKey", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "Key Handler : %1").arg( *phKey ));
    }

    return rv;
}

int CryptokiAPI::CreateObject(
        CK_SESSION_HANDLE hSession,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulTemplateCnt,
        CK_OBJECT_HANDLE_PTR phObject )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_CreateObject( hSession, pTemplate, ulTemplateCnt, phObject );
    ms = timer.elapsed();

    strIn.sprintf( "C_CreateObject( SESSION_HANDLE = %u, TEMPLATE_PTR = @%p ATTRIBTE_COUNT = %d, OBJECT_HANDL_PTR = @%p )",
                   hSession, pTemplate, ulTemplateCnt, phObject );
    manApplet->dlog( strIn );

    logTemplate( pTemplate, ulTemplateCnt );

    logResult( "C_CreateObject", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "Object Handler : %1").arg( *phObject ));
    }

    return rv;
}

int CryptokiAPI::DestroyObject( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_DestroyObject( hSession, hObject );
    ms = timer.elapsed();

    strIn.sprintf( "C_DestroyObject( SESSION_HANDLE = %u, OBJECT_HANDLE = %u )", hSession, hObject );
    manApplet->dlog( strIn );

    logResult( "C_DestroyObject", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::DigestInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_DigestInit( hSession, pMechanism );
    ms = timer.elapsed();

    strIn.sprintf( "C_DigestInit( SESSION_HANDLE = %u, MECHANISM_PTR = @%p )", hSession, pMechanism );
    manApplet->dlog( strIn );

    logResult( "C_DigestInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::DigestUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_DigestUpdate( hSession, pPart, ulPartLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_DigestUpdate( SESSION_HANDLE = %u, PART_PTR = @%p, PART_LEN = %d )",
                   hSession, pPart, ulPartLen );
    manApplet->dlog( strIn );

    logResult( "C_DigestUpdate", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::DigestKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_DigestKey( hSession, hKey );
    ms = timer.elapsed();

    logResult( "C_DigestKey", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::DigestFinal( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_DigestFinal( hSession, pDigest, pulDigestLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_DigestFinal( SESSION_HANDLE = %u, DIGEST_PTR = @%p DIGEST_LEN_PTR = @%p",
                   hSession, pDigest, pulDigestLen );
    manApplet->dlog( strIn );

    logResult( "C_DigestFinal", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "DigestLen : %1").arg( *pulDigestLen ));

        if( pDigest )
        {
            manApplet->dlog( QString( "Digest : %1").arg( getHexString( pDigest, *pulDigestLen )));
        }
    }

    return rv;
}

int CryptokiAPI::Digest( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_Digest( hSession, pData, ulDataLen, pDigest, pulDigestLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_Digest( SESSION_HANDLE = %u, DATA_PTR = @%p, DATA_LEN = %d, DIGEST_PTR = @%p, DIGEST_LEN_PTR = @%p )",
                   hSession, pData, ulDataLen, pDigest, pulDigestLen );
    manApplet->dlog( strIn );


    logResult( "C_Digest", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "DigestLen : %1").arg( *pulDigestLen ));

        if( pDigest )
        {
            manApplet->dlog( QString( "Digest : %1").arg( getHexString( pDigest, *pulDigestLen )));
        }
    }

    return rv;
}

int CryptokiAPI::SignInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_SignInit( hSession, pMechanism, hKey );
    ms = timer.elapsed();

    strIn.sprintf( "C_SignInit( SESSION_HANDLE = %u, MECHANISM_PTR = @%p, OBJECT_HANDLE = %u )",
                   hSession, pMechanism, hKey );
    manApplet->dlog( strIn );

    logResult( "C_SignInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::SignUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_SignUpdate( hSession, pPart, ulPartLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_SignUpdate( SESSION_HANDLE = %u, PART_PTR = @%p, PART_LEN = %d )",
                   hSession, pPart, ulPartLen );
    manApplet->dlog( strIn );


    logResult( "C_SignUpdate", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::SignFinal( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSign, CK_ULONG_PTR pulSignLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_SignFinal( hSession, pSign, pulSignLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_SignFinal( SESSION_HANDLE = %u, SIGN_PTR = @%p, SIGN_LEN_PTR = @%p )",
                   hSession, pSign, pulSignLen );
    manApplet->dlog( strIn );

    logResult( "C_SignFinal", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "SignLen : %1").arg( *pulSignLen ));
        if( pSign )
        {
            manApplet->dlog( QString( "Sign : %1").arg( getHexString( pSign, *pulSignLen )));
        }
    }

    return rv;
}

int CryptokiAPI::Sign( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSign, CK_ULONG_PTR pulSignLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_Sign( hSession, pData, ulDataLen, pSign, pulSignLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_Sign( SESSION_HANDLE = %u, DATA_PTR = @%p, DATA_LEN = %d, SIGN_PTR = @%p, SIGN_LEN_PTR = @%p )",
                   hSession, pData, ulDataLen, pSign, pulSignLen );
    manApplet->dlog( strIn );

    logResult( "C_Sign", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "SignLen : %1").arg( *pulSignLen ));
        if( pSign )
        {
            manApplet->dlog( QString( "Sign : %1").arg( getHexString( pSign, *pulSignLen )));
        }
    }

    return rv;
}

int CryptokiAPI::SignRecoverInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_SignRecoverInit( hSession, pMechanism, hKey );
    ms = timer.elapsed();

    strIn.sprintf( "C_SignRecoverInit( SESSION_HANDLE = %u, MECHANISM_PTR = @%p, OBJECT_HANDLE = %u )",
                   hSession, pMechanism, hKey );
    manApplet->dlog( strIn );

    logResult( "C_SignRecoverInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::SignRecover( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSign, CK_ULONG_PTR pulSignLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_SignRecover( hSession, pData, ulDataLen, pSign, pulSignLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_SignRecover( SESSION_HANDLE = %u, DATA_PTR = @%p, DATA_LEN = %d, SIGN_PTR = @%p, SIGN_LEN_PTR = @%p )",
                   hSession, pData, ulDataLen, pSign, pulSignLen );
    manApplet->dlog( strIn );

    logResult( "C_SignRecover", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "SignLen : %1").arg( *pulSignLen ));
        if( pSign )
        {
            manApplet->dlog( QString( "Sign : %1").arg( getHexString( pSign, *pulSignLen )));
        }
    }

    return rv;
}

int CryptokiAPI::VerifyInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_VerifyInit( hSession, pMechanism, hKey );
    ms = timer.elapsed();

    strIn.sprintf( "C_VerifyInit( SESSION_HANDLE = %u, MECHANISM_PTR = @%p, OBJECT_HANDLE = %u )",
                   hSession, pMechanism, hKey );
    manApplet->dlog( strIn );

    logResult( "C_VerifyInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::VerifyUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_VerifyUpdate( hSession, pPart, ulPartLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_VerifyUpdate( SESSION_HANDLE = %u, PART_PTR = @%p, PART_LEN = %d )",
                   hSession, pPart, ulPartLen );
    manApplet->dlog( strIn );

    logResult( "C_VerifyUpdate", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::VerifyFinal( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSign, CK_ULONG ulSignLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_VerifyFinal( hSession, pSign, ulSignLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_VerifyFinal( SESSION_HANDLE = %u, SIGN_PTR = @%p, SIGN_LEN = %d )",
                   hSession, pSign, ulSignLen );
    manApplet->dlog( strIn );

    logResult( "C_VerifyFinal", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::Verify( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSign, CK_ULONG ulSignLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_Verify( hSession, pData, ulDataLen, pSign, ulSignLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_Verify( SESSION_HANDLE = %u, DATA_PTR = @%p, DATA_LEN = %d, SIGN_PTR = @%p, SIGN_LEN = %d )",
                   hSession, pData, ulDataLen, pSign, ulSignLen );
    manApplet->dlog( strIn );

    logResult( "C_Verify", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::VerifyRecoverInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_VerifyRecoverInit( hSession, pMechanism, hKey );
    ms = timer.elapsed();

    strIn.sprintf( "C_VerifyRecoverInit( SESSION_HANDLE = %u, MECHANISM_PTR = @%p, OBJECT_HANDLE = %u )",
                   hSession, pMechanism, hKey );
    manApplet->dlog( strIn );

    logResult( "C_VerifyRecoverInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::VerifyRecover( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSign, CK_ULONG ulSignLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_VerifyRecover( hSession, pSign, ulSignLen, pData, pulDataLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_VerifyRecover( SESSION_HANDLE = %u, SIGN_PTR = @%p, SIGN_LEN = %d, DATA_PTR = @%p, DATA_LEN_PTR = @%p )",
                   hSession, pSign, ulSignLen, pData, pulDataLen );
    manApplet->dlog( strIn );

    logResult( "C_VerifyRecover", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "DataLen : %1").arg( *pulDataLen ));
        if( pSign )
        {
            manApplet->dlog( QString( "Data : %1").arg( getHexString( pData, *pulDataLen )));
        }
    }

    return rv;
}

int CryptokiAPI::EncryptInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_EncryptInit( hSession, pMechanism, hKey );
    ms = timer.elapsed();

    strIn.sprintf( "C_EncryptInit( SESSION_HANDLE = %u, MECHANISM_PTR = @%p, OBJECT_HANDLE = %u )",
                   hSession, pMechanism, hKey );
    manApplet->dlog( strIn );

    logResult( "C_EncryptInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::EncryptUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncPart, CK_ULONG_PTR pulEncPartLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_EncryptUpdate( hSession, pPart, ulPartLen, pEncPart, pulEncPartLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_EncryptUpdate( SESSION_HANDLE = %u, PART_PTR = @%p, PART_LEN = %d, ENC_PART_PTR = @%p, ENC_PART_LEN_PTR = @%p )",
                   hSession, pPart, ulPartLen, pEncPart, pulEncPartLen );
    manApplet->dlog( strIn );

    logResult( "C_EncryptUpdate", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "EncPartLen : %1").arg( *pulEncPartLen));

        if( pEncPart )
        {
            manApplet->dlog( QString( "EncPart : %1").arg( getHexString( pEncPart, *pulEncPartLen)));
        }
    }

    return rv;
}

int CryptokiAPI::EncryptFinal( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncPart, CK_ULONG_PTR pulLastEncPartLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_EncryptFinal( hSession, pLastEncPart, pulLastEncPartLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_EncryptFinal( SESSION_HANDLE = %u, LAST_ENC_PART_PTR = %p, LAST_ENC_PART_LEN_PTR = %d )",
                   hSession, pLastEncPart, pulLastEncPartLen );
    manApplet->dlog( strIn );

    logResult( "C_EncryptFinal", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "LastEncPartLen : %1" ).arg( *pulLastEncPartLen ));
        if( pLastEncPart )
        {
            manApplet->dlog( QString( "LastEncPart : %1").arg( getHexString( pLastEncPart, *pulLastEncPartLen)));
        }
    }

    return rv;
}

int CryptokiAPI::Encrypt( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncData, CK_ULONG_PTR pulEncDataLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_Encrypt( hSession, pData, ulDataLen, pEncData, pulEncDataLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_Encrypt( SESSION_HANDLE = %u, DATA_PTR = @%p, DATA_LEN = %d, ENC_DATA_PTR = @%p, ENC_DATA_LEN_PTR = @%p )",
                   hSession, pData, ulDataLen, pEncData, pulEncDataLen );
    manApplet->dlog( strIn );

    logResult( "C_Encrypt", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "EncDataLen : %1").arg( *pulEncDataLen));

        if( pEncData )
        {
            manApplet->dlog( QString( "EncData : %1").arg( getHexString( pEncData, *pulEncDataLen)));
        }
    }

    return rv;
}

int CryptokiAPI::DecryptInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_DecryptInit( hSession, pMechanism, hKey );
    ms = timer.elapsed();

    strIn.sprintf( "C_DecryptInit( SESSION_HANDLE = %u, MECHANISM_PTR = @%p, OBJECT_HANDLE = %u )",
                   hSession, pMechanism, hKey );
    manApplet->dlog( strIn );

    logResult( "C_DecryptInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::DecryptUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncPart, CK_ULONG ulEncPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_DecryptUpdate( hSession, pEncPart, ulEncPartLen, pPart, pulPartLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_DecryptUpdate( SESSION_HANDLE = %u, ENC_PART_PTR = @%p, ENC_PART_LEN = %d, PART_PTR = @%p, PART_LEN_PTR = @%p )",
                   hSession, pEncPart, ulEncPartLen, pPart, pulPartLen );
    manApplet->dlog( strIn );

    logResult( "C_DecryptUpdate", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "DecPartLen : %1").arg( *pulPartLen ));

        if( pPart )
        {
            manApplet->dlog( QString( "DecPart : %1").arg( getHexString( pPart, *pulPartLen )));
        }
    }

    return rv;
}

int CryptokiAPI::DecryptFinal( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_DecryptFinal( hSession, pLastPart, pulLastPartLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_DecryptFinal( SESSION_HANDLE = %u, LAST_PART_PTR = @%p, LAST_PART_LEN_PTR = %d )",
                   hSession, pLastPart, pulLastPartLen );
    manApplet->dlog( strIn );

    logResult( "C_DecryptFinal", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "DecLastPartLen : %1").arg( *pulLastPartLen ));

        if( pLastPart )
        {
            manApplet->dlog( QString( "DecLastPart : %1").arg( getHexString( pLastPart, *pulLastPartLen )));
        }
    }

    return rv;
}

int CryptokiAPI::Decrypt( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncData, CK_ULONG ulEncDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_Decrypt( hSession, pEncData, ulEncDataLen, pData, pulDataLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_Decrypt( SESSION_HANDLE = %u, ENC_DATA_PTR = @%p, ENC_DATA_LEN = %d, DATA_PTR = @%p, DATA_LEN_PTR = @%p )",
                   hSession, pEncData, ulEncDataLen, pData, pulDataLen );
    manApplet->dlog( strIn );

    logResult( "C_Decrypt", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "DecDataLen : %1").arg( *pulDataLen ));

        if( pData )
        {
            manApplet->dlog( QString( "DecData : %1").arg( getHexString( pData, *pulDataLen )));
        }
    }

    return rv;
}

int CryptokiAPI::InitPIN( CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_InitPIN( hSession, pPin, ulPinLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_InitPIN( SESSION_HANDLE = %u, PIN_PTR = @%p, PIN_LEN = %d )",
                   hSession, pPin, ulPinLen );
    manApplet->dlog( strIn );

    logResult( "C_InitPIN", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::SetPIN( CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_SetPIN( hSession, pOldPin, ulOldLen, pNewPin, ulNewLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_SetPIN( SESSION_HANDLE = %u, OLD_PIN_PTR = @%p, OLD_PIN_LEN = %d, NEW_PIN_PTR = @%p, NEW_PIN_LEN = %d )",
                   hSession, pOldPin, ulOldLen, pNewPin, ulNewLen );
    manApplet->dlog( strIn );

    logResult( "C_SetPIN", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::InitToken( CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_InitToken( slotID, pPin, ulPinLen, pLabel );
    ms = timer.elapsed();

    strIn.sprintf( "C_InitToken( SLOT_ID = %u, PIN_PTR = @%p, PIN_LEN = %d, LABEL_PTR = @%p",
                   slotID,
                   pPin,
                   ulPinLen,
                   pLabel );
    manApplet->dlog( strIn );

    logResult( "C_InitToken", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::SeedRandom( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_SeedRandom( hSession, pSeed, ulSeedLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_SeedRandom( SESSION_HANDLE = %u, SEED_PTR = @%p, SEED_LEN = %d )",
                   hSession, pSeed, ulSeedLen );
    manApplet->dlog( strIn );

    logResult( "C_SeedRandom", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::GenerateRandom( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GenerateRandom( hSession, pRandomData, ulRandomLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_GenerateRandom( SESSION_HANDLE = %u, RANDOM_DATA_PTR = @%p, RANDOM_DATA_LEN = %d )",
                   hSession, pRandomData, ulRandomLen );
    manApplet->dlog( strIn );

    logResult( "C_GenerateRandom", rv, ms );

    if( rv == CKR_OK )
    {
        if( pRandomData )
        {
            manApplet->dlog( QString( "Random Data : %1").arg( getHexString( pRandomData, ulRandomLen )));
        }
    }

    return rv;
}

int CryptokiAPI::GetOperationState( CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR pOperationState,
                       CK_ULONG_PTR pulOperationStateLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetOperationState( hSession, pOperationState, pulOperationStateLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_GetOperationState( SESSION_HANDLE = %u, OperationState_ptr = @%p, OperationStateLen = @%p )",
                   hSession, pOperationState, pulOperationStateLen );
    manApplet->dlog( strIn );

    logResult( "C_GetOperationState", rv, ms );

    if( rv == CKR_OK )
    {
        if( pOperationState ) manApplet->dlog( QString( "Operation State : %1").arg( getHexString(pOperationState, *pulOperationStateLen )));
    }

    return rv;
}

int CryptokiAPI::SetOperationState( CK_SESSION_HANDLE hSession,
                                    CK_BYTE_PTR pOperationState,
                                    CK_ULONG ulOperationStateLen,
                                    CK_OBJECT_HANDLE hEncryptionKey,
                                    CK_OBJECT_HANDLE hAuthenticationKey )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_SetOperationState( hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey );
    ms = timer.elapsed();

    strIn.sprintf( "C_GetOperationState( SESSION_HANDLE = %u, OperationState_ptr = @%p, OperationStateLen = %u, EncryptKeyHandle = %u, AuthenticationKeyHandle = %u )",
                   hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey );
    manApplet->dlog( strIn );


    logResult( "C_GetOperationState", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}


int CryptokiAPI::DeriveKey( CK_SESSION_HANDLE hSession,
               CK_MECHANISM_PTR pMechanism,
               CK_OBJECT_HANDLE hBaseKey,
               CK_ATTRIBUTE_PTR pTemplate,
               CK_ULONG ulTemplateCnt,
               CK_OBJECT_HANDLE_PTR phKey )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_DeriveKey( hSession, pMechanism, hBaseKey, pTemplate, ulTemplateCnt, phKey );
    ms = timer.elapsed();

    strIn.sprintf( "C_DeriveKey( SESSION_HANDLE = %u, MECHANISM_PTR = @%p, OBJECT_HANDLE = %u, TEMPLATE = @%p ATTRIBUTE_COUNT = %d, OBJECT_HANDLE_PTR = @%p )",
                   hSession, pMechanism, hBaseKey, pTemplate, ulTemplateCnt, phKey );
    manApplet->dlog( strIn );

    logTemplate( pTemplate, ulTemplateCnt );

    logResult( "C_DeriveKey", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "Object Handler : %1").arg( *phKey ));
    }

    return rv;
}

int CryptokiAPI::WrapKey( CK_SESSION_HANDLE hSession,
             CK_MECHANISM_PTR pMechanism,
             CK_OBJECT_HANDLE hWrappingKey,
             CK_OBJECT_HANDLE hKey,
             CK_BYTE_PTR pWrappedKey,
             CK_ULONG_PTR pulWrappedKeyLen )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_WrapKey( hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen );
    ms = timer.elapsed();

    strIn.sprintf( "C_WrapKey( SESSION_HANDLE = %u, MECHANISM_PTR = @%p, OBJECT_HANDLE = %u, OBJECT_HANDLE = %u, WRAPPED_KEY_PTR = @%p, WRAPPED_KEY_LEN_PTR = @%p )",
                   hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen );
    manApplet->dlog( strIn );

    logResult( "C_WrapKey", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "WrappedKeyLen : %1").arg( *pulWrappedKeyLen ));
        if( pWrappedKey ) manApplet->dlog( QString( "WrappedKey: %1").arg( getHexString( pWrappedKey, *pulWrappedKeyLen )));
    }

    return rv;
}

int CryptokiAPI::UnwrapKey( CK_SESSION_HANDLE hSession,
               CK_MECHANISM_PTR pMechanism,
               CK_OBJECT_HANDLE hUnwrappingKey,
               CK_BYTE_PTR pWrappedKey,
               CK_ULONG ulWrappedKeyLen,
               CK_ATTRIBUTE_PTR pTemplate,
               CK_ULONG ulTemplateCnt,
               CK_OBJECT_HANDLE_PTR phKey )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_UnwrapKey( hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulTemplateCnt, phKey );
    ms = timer.elapsed();

    strIn.sprintf( "C_UnwrapKey( SESSION_HANDLE = %u, MECHANISM_PTR = %p, OBJECT_HANDLE = %u, WRAPPED_KEY_PTR = %p, WRAPPED_KEY_LEN = %d, TEMPLATE = @%p, ATTRIBUTE_COUNT = %d, OBJECT_HANDLE_PTR = %u )",
                   hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulTemplateCnt, phKey );
    manApplet->dlog( strIn );

    logTemplate( pTemplate, ulTemplateCnt );

    logResult( "C_UnwrapKey", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "Unwrapped Key Handler : %1").arg( *phKey ));
    }

    return rv;
}

int CryptokiAPI::WaitForSlotEvent( CK_FLAGS uFlags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_WaitForSlotEvent( uFlags, pSlot, pReserved );
    ms = timer.elapsed();

    strIn.sprintf( "C_WaitForSlotEvent( FLAGS = %u, SLOT_ID_PTR = @%p, RESERVER = @%p )",
                   uFlags, pSlot, pReserved );
    manApplet->dlog( strIn );

    logResult( "C_WaitForSlotEvent", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

QString CryptokiAPI::getLastError()
{
    QString strError = p11_ctx_->sLastLog;

    return strError;
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
