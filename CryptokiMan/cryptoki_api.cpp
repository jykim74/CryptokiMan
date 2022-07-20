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

    strIn.sprintf( "pReserved = %p", pReserved );
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

    strIn.sprintf( "pReserved = %p", pReserved );
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

int CryptokiAPI::GetAttributeValue( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pAttribute, CK_ULONG uAttributeCnt )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetAttributeValue( hSession, hObject, pAttribute, uAttributeCnt );
    ms = timer.elapsed();

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDLE = %ud", hObject );
    manApplet->dlog( strIn );

    logTemplate( pAttribute, uAttributeCnt );

    logResult( QString("C_GetAttributeValue[%1:%2]")
               .arg(pAttribute->type)
               .arg(JS_PKCS11_GetCKAName(pAttribute->type)), rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDLE = %ud", hObject );
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

    strIn.sprintf( "SLOT_ID = %d", slotID );
    manApplet->dlog( strIn );

    strIn.sprintf( "FLAGS = %d", flags );
    manApplet->dlog( strIn );

    strIn.sprintf( "APPLICATION_PTR = %p", pApplication );
    manApplet->dlog( strIn );

    strIn.sprintf( "NOTIFY = %p", Notify );
    manApplet->dlog( strIn );

    strIn.sprintf( "SESSION_HANDLE_PTR = %p", phSession );
    manApplet->dlog( strIn );

    logResult( "C_OpenSession", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
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

    strIn.sprintf( "SLOT_ID = %d", slotID );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "USER_TYPE = %d", userType );
    manApplet->dlog( strIn );

    strIn.sprintf( "Pin = %s", pPin );
    manApplet->dlog( strIn );

    strIn.sprintf( "PinLen = %d", ulPinLen );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "MECHANISM_PTR = %p", pMechanism );
    manApplet->dlog( strIn );

    logTemplate( pPubTemplate, ulPubTemplateCnt );
    logTemplate( pPriTemplate, ulPriTemplateCnt );

    strIn.sprintf( "OBJECT_HANDL_PTR = %p", phPubKey );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDL_PTR = %p", phPriKey );
    manApplet->dlog( strIn );

    logResult( "C_GenerateKeyPair", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "MECHANISM_PTR = %p", pMechanism );
    manApplet->dlog( strIn );

    logTemplate( pTemplate, ulTemplateCnt );

    strIn.sprintf( "OBJECT_HANDL_PTR = %p", phKey );
    manApplet->dlog( strIn );

    logResult( "C_GenerateKey", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    logTemplate( pTemplate, ulTemplateCnt );

    strIn.sprintf( "OBJECT_HANDL_PTR = %p", phObject );
    manApplet->dlog( strIn );

    logResult( "C_CreateObject", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDLE = %ud", hObject );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "MECHANISM_PTR = %p", pMechanism );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "PART_PTR = %p", pPart );
    manApplet->dlog( strIn );

    strIn.sprintf( "PART_LEN = %d", ulPartLen );
    manApplet->dlog( strIn );

    logResult( "C_DigestUpdate", rv, ms );

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "DIGEST_PTR = %p", pDigest );
    manApplet->dlog( strIn );

    strIn.sprintf( "DIGEST_LEN_PTR = %p", pulDigestLen );
    manApplet->dlog( strIn );

    logResult( "C_DigestFinal", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "DATA_PTR = %p", pData );
    manApplet->dlog( strIn );

    strIn.sprintf( "DATA_LEN = %d", ulDataLen );
    manApplet->dlog( strIn );

    strIn.sprintf( "DIGEST_PTR = %p", pDigest );
    manApplet->dlog( strIn );

    strIn.sprintf( "DIGEST_LEN_PTR = %p", pulDigestLen );
    manApplet->dlog( strIn );

    logResult( "C_Digest", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "MECHANISM_PTR = %p", pMechanism );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDLE = %ud", hKey );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "PART_PTR = %p", pPart );
    manApplet->dlog( strIn );

    strIn.sprintf( "PART_LEN = %d", ulPartLen );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "SIGN_PTR = %p", pSign );
    manApplet->dlog( strIn );

    strIn.sprintf( "SIGN_LEN_PTR = %p", pulSignLen );
    manApplet->dlog( strIn );

    logResult( "C_SignFinal", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "DATA_PTR = %p", pData );
    manApplet->dlog( strIn );

    strIn.sprintf( "DATA_LEN = %d", ulDataLen );
    manApplet->dlog( strIn );

    strIn.sprintf( "SIGN_PTR = %p", pSign );
    manApplet->dlog( strIn );

    strIn.sprintf( "SIGN_LEN_PTR = %p", pulSignLen );
    manApplet->dlog( strIn );

    logResult( "C_Sign", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "MECHANISM_PTR = %p", pMechanism );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDLE = %ud", hKey );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "PART_PTR = %p", pPart );
    manApplet->dlog( strIn );

    strIn.sprintf( "PART_LEN = %d", ulPartLen );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "SIGN_PTR = %p", pSign );
    manApplet->dlog( strIn );

    strIn.sprintf( "SIGN_LEN = %d", ulSignLen );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "DATA_PTR = %p", pData );
    manApplet->dlog( strIn );

    strIn.sprintf( "DATA_LEN = %d", ulDataLen );
    manApplet->dlog( strIn );

    strIn.sprintf( "SIGN_PTR = %p", pSign );
    manApplet->dlog( strIn );

    strIn.sprintf( "SIGN_LEN = %d", ulSignLen );
    manApplet->dlog( strIn );

    logResult( "C_Verify", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "MECHANISM_PTR = %p", pMechanism );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDLE = %ud", hKey );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "PART_PTR = %p", pPart );
    manApplet->dlog( strIn );

    strIn.sprintf( "PART_LEN = %d", ulPartLen );
    manApplet->dlog( strIn );

    strIn.sprintf( "ENC_PART_PTR = %p", pEncPart );
    manApplet->dlog( strIn );

    strIn.sprintf( "ENC_PART_LEN_PTR = %p", pulEncPartLen );
    manApplet->dlog( strIn );

    logResult( "C_EncryptUpdate", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "LAST_ENC_PART_PTR = %p", pLastEncPart );
    manApplet->dlog( strIn );

    strIn.sprintf( "LAST_ENC_PART_LEN_PTR = %d", pulLastEncPartLen );
    manApplet->dlog( strIn );

    logResult( "C_EncryptFinal", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "DATA_PTR = %p", pData );
    manApplet->dlog( strIn );

    strIn.sprintf( "DATA_LEN = %d", ulDataLen );
    manApplet->dlog( strIn );

    strIn.sprintf( "ENC_DATA_PTR = %p", pEncData );
    manApplet->dlog( strIn );

    strIn.sprintf( "ENC_DATA_LEN_PTR = %p", pulEncDataLen );
    manApplet->dlog( strIn );

    logResult( "C_Encrypt", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "MECHANISM_PTR = %p", pMechanism );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDLE = %ud", hKey );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "ENC_PART_PTR = %p", pEncPart );
    manApplet->dlog( strIn );

    strIn.sprintf( "ENC_PART_LEN = %d", ulEncPartLen );
    manApplet->dlog( strIn );

    strIn.sprintf( "PART_PTR = %p", pPart );
    manApplet->dlog( strIn );

    strIn.sprintf( "PART_LEN_PTR = %p", pulPartLen );
    manApplet->dlog( strIn );

    logResult( "C_DecryptUpdate", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "LAST_PART_PTR = %p", pLastPart );
    manApplet->dlog( strIn );

    strIn.sprintf( "LAST_PART_LEN_PTR = %d", pulLastPartLen );
    manApplet->dlog( strIn );

    logResult( "C_DecryptFinal", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "ENC_DATA_PTR = %p", pEncData );
    manApplet->dlog( strIn );

    strIn.sprintf( "ENC_DATA_LEN = %d", ulEncDataLen );
    manApplet->dlog( strIn );

    strIn.sprintf( "DATA_PTR = %p", pData );
    manApplet->dlog( strIn );

    strIn.sprintf( "DATA_LEN_PTR = %p", pulDataLen );
    manApplet->dlog( strIn );

    logResult( "C_Decrypt", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "PIN_PTR = %p", pPin );
    manApplet->dlog( strIn );

    strIn.sprintf( "PIN_LEN = %d", ulPinLen );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "OLD_PIN_PTR = %p", pOldPin );
    manApplet->dlog( strIn );

    strIn.sprintf( "OLD_PIN_LEN = %d", ulOldLen );
    manApplet->dlog( strIn );

    strIn.sprintf( "NEW_PIN_PTR = %p", pNewPin );
    manApplet->dlog( strIn );

    strIn.sprintf( "NEW_PIN_LEN = %d", ulNewLen );
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

    strIn.sprintf( "SLOT_ID = %ud", slotID );
    manApplet->dlog( strIn );

    strIn.sprintf( "PIN_PTR = %p", pPin );
    manApplet->dlog( strIn );

    strIn.sprintf( "PIN_LEN = %d", ulPinLen );
    manApplet->dlog( strIn );

    strIn.sprintf( "LABEL_PTR = %p", pLabel );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "SEED_PTR = %p", pSeed );
    manApplet->dlog( strIn );

    strIn.sprintf( "SEED_LEN = %d", ulSeedLen );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "RANDOM_DATA_PTR = %p", pRandomData );
    manApplet->dlog( strIn );

    strIn.sprintf( "RANDOM_DATA_LEN = %d", ulRandomLen );
    manApplet->dlog( strIn );

    logResult( "C_GenerateRandom", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "OperationState_ptr = %p", pOperationState );
    manApplet->dlog( strIn );

    strIn.sprintf( "OperationStateLen = %d", *pulOperationStateLen );
    manApplet->dlog( strIn );

    logResult( "C_GetOperationState", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::SetOperationState( CK_SESSION_HANDLE hSession,
                                    CK_OBJECT_HANDLE hObject,
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "ObjectHandle = %ud", hObject );
    manApplet->dlog( strIn );

    strIn.sprintf( "OperationState_ptr = %p", pOperationState );
    manApplet->dlog( strIn );

    strIn.sprintf( "OperationStateLen = %ud", ulOperationStateLen );
    manApplet->dlog( strIn );

    strIn.sprintf( "EncryptKeyHandle = %ud", hEncryptionKey );
    manApplet->dlog( strIn );

    strIn.sprintf( "AuthenticationKeyHandle = %ud", hAuthenticationKey );
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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "MECHANISM_PTR = %p", pMechanism );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDLE = %ud", hBaseKey );
    manApplet->dlog( strIn );

    logTemplate( pTemplate, ulTemplateCnt );

    strIn.sprintf( "OBJECT_HANDLE_PTR = %p", phKey );
    manApplet->dlog( strIn );

    logResult( "C_DeriveKey", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "MECHANISM_PTR = %p", pMechanism );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDLE = %ud", hWrappingKey );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDLE = %ud", hKey );
    manApplet->dlog( strIn );

    strIn.sprintf( "WRAPPED_KEY_PTR = %p", pWrappedKey );
    manApplet->dlog( strIn );

    strIn.sprintf( "WRAPPED_KEY_LEN_PTR = %p", pulWrappedKeyLen );

    logResult( "C_WrapKey", rv, ms );

    if( rv == CKR_OK )
    {

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

    strIn.sprintf( "SESSION_HANDLE = %ud", hSession );
    manApplet->dlog( strIn );

    strIn.sprintf( "MECHANISM_PTR = %p", pMechanism );
    manApplet->dlog( strIn );

    strIn.sprintf( "OBJECT_HANDLE = %ud", hUnwrappingKey );

    strIn.sprintf( "WRAPPED_KEY_PTR = %p", pWrappedKey );
    manApplet->dlog( strIn );

    strIn.sprintf( "WRAPPED_KEY_LEN = %d", ulWrappedKeyLen );
    manApplet->dlog( strIn );

    logTemplate( pTemplate, ulTemplateCnt );

    strIn.sprintf( "OBJECT_HANDLE_PTR = %ud", phKey );
    manApplet->dlog( strIn );

    logResult( "C_UnwrapKey", rv, ms );

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
