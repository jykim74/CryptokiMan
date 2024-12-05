/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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
        JS_PKCS11_ReleaseLibrary( &p11_ctx_ );
    }

    p11_ctx_ = pCTX;
}

CK_SESSION_HANDLE CryptokiAPI::getSessionHandle()
{
    if( p11_ctx_ == NULL ) return -1;

    return p11_ctx_->hSession;
}

int CryptokiAPI::getAttrType( CK_ATTRIBUTE_TYPE nType )
{
    switch ( nType ) {
    case CKA_KEY_TYPE :
        return ATTR_VAL_KEY_NAME;

    case CKA_CLASS :
        return ATTR_VAL_OBJECT_NAME;

    case CKA_LABEL :
    case CKA_APPLICATION:
    case CKA_URL :
        return ATTR_VAL_STRING;

    case CKA_VALUE_LEN:
    case CKA_VALUE_BITS:
    case CKA_MODULUS_BITS:
    case CKA_PRIME_BITS:
    case CKA_SUBPRIME_BITS:
        return ATTR_VAL_LEN;

    case CKA_START_DATE:
    case CKA_END_DATE:
        return ATTR_VAL_DATE;

    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_MODIFIABLE:
    case CKA_COPYABLE:
    case CKA_DESTROYABLE:
    case CKA_TRUSTED:
    case CKA_LOCAL:
    case CKA_DERIVE:
    case CKA_ENCRYPT:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
    case CKA_WRAP:
    case CKA_SENSITIVE:
    case CKA_DECRYPT:
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_UNWRAP:
    case CKA_EXTRACTABLE:
    case CKA_ALWAYS_SENSITIVE:
    case CKA_NEVER_EXTRACTABLE:
    case CKA_WRAP_WITH_TRUSTED:
    case CKA_ALWAYS_AUTHENTICATE:
        return ATTR_VAL_BOOL;

    default:
        return ATTR_VAL_HEX;
    }
}

int CryptokiAPI::openLibrary( const QString strPath )
{
    int ret = 0;

    ret = JS_PKCS11_LoadLibrary( (JP11_CTX **)&p11_ctx_, strPath.toLocal8Bit().toStdString().c_str() );

    return ret;
}

int CryptokiAPI::unloadLibrary()
{
    if( p11_ctx_ ) JS_PKCS11_ReleaseLibrary( (JP11_CTX **)&p11_ctx_ );
    manApplet->log( "Cryptoki library has been released" );
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

    strIn = QString( "C_Initialize( pReserved = @0x%1 )" ).arg( (quintptr)pReserved );
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

    strIn = QString( "C_Finalize( pReserved = @0x%1 )").arg( (quintptr) pReserved );
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

    strIn = QString( "C_GetSlotList( token_present = %1, slot_id = @0x%2, slot_count = @0x%3 )" ).arg( bVal ).arg( (quintptr)pSlotList ).arg( (quintptr)pSlotCnt );
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

    strIn = QString( "C_GetInfo( INFO_PTR = @0x%1 )").arg((quintptr) pInfo );

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

    strIn = QString( "C_GetSlotInfo( SLOT_ID = %1, SLOT_INFO = @0x%2 )" ).arg( slotID ).arg((quintptr) pSlotInfo );
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

    strIn = QString( "C_GetTokenInfo( SLOT_ID = %1, TOKEN_INFO = @0x%2 )" ).arg( slotID ).arg( (quintptr) pTokenInfo );
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

    strIn = QString( "C_GetMechanismList( SLOT_ID = %1, MECHANISM_TYPE_PTR = @0x%2, MECHANISM_COUNT_PTR = @0x%3 )" )
                    .arg(slotID).arg( (quintptr) pMechList ).arg( (quintptr)puMechCount );
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

    strIn = QString( "C_GetMechanismInfo( SLOT_ID = %1, MECHANISM_TYPE = %2, MECHAINSM_INFO_PTR = @0x%3 )" )
                .arg(slotID ).arg( iMechType ).arg((quintptr) pInfo );

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

    strIn = QString( "C_GetSessionInfo( SESSION_HANDLE = %1, SESSION_INFO_PTR = @0x%2 )").arg( hSession ).arg((quintptr) pSessionInfo );
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

    strIn = QString( "C_FindObjectsInit( SESSION_HANDLE = %1, ATTRIBUTE_PTR = @0x%2, ATTRIBUTE_COUNT = %3 )" )
                .arg( hSession ).arg((quintptr) pTemplate ).arg( uCount );
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

    strIn = QString( "C_FindObjects( SESSION_HANDLE = %1, OBJECT_HANDLE_PTR = @0x%2, MAX_OBJECT_COUNT = %3, OBJECT_COUNT_PTR = @0x%4 )" )
                .arg( hSession ).arg( (quintptr)phObject ).arg( uMaxObjCount ).arg((quintptr) puObjCount );
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

    strIn = QString( "C_FindObjectsFinal( SESSION_HANDLE = %1 )" ).arg( hSession );
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

    strIn = QString( "C_GetObjectSize( SESSION_HANDLE = %1, OBJECT_HANDLE = %2, OBJECT_SIZE_PTR = @0x%3 )" )
                .arg( hSession ).arg( hObject ).arg( (quintptr)puSize );
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

    strIn = QString( "C_GetAttributeValue( SESSION_HANDLE = %1, OBJECT_HANDLE = %2, ATTRIBUTE_PTR = @0x%3 ATTRIBUTE_COUNT = %4 )")
                .arg( hSession ).arg( hObject ).arg( (quintptr)pAttribute ).arg( uAttributeCnt );
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
        fprintf( stderr, "failed to execute C_GetAttributeValue(%s:%s:%d)\n", JS_PKCS11_GetCKAName(attrType),JS_PKCS11_GetErrorMsg(rv), rv );
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

int CryptokiAPI::GetAttributeListValue( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pAttribute, CK_ULONG uAttributeCnt )
{
    int rv;
    if( hSession <= 0 ) return -1;

    rv = GetAttributeValue( hSession, hObject, pAttribute, uAttributeCnt );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "failed to execute C_GetAttributeValue(%s:%d)\n", JS_PKCS11_GetErrorMsg(rv), rv );
        return rv;
    }

    for( int i = 0; i < uAttributeCnt; i++ )
    {
        if( pAttribute[i].ulValueLen > 0 && pAttribute[i].pValue == NULL )
        {
            pAttribute[i].pValue = (CK_BYTE_PTR)JS_calloc( 1, pAttribute[i].ulValueLen );
        }
    }

    rv = GetAttributeValue( hSession, hObject, pAttribute, uAttributeCnt );

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

    strIn = QString( "C_SetAttributeValue( SESSION_HANDLE = %1, OBJECT_HANDLE = %2, ATTRIBUTE_PTR = @0x%3 ATTRIBUTE_COUNT = %4 )")
                .arg( hSession ).arg( hObject ).arg( (quintptr)pAttribute ).arg( uAttributeCnt );
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

    strIn = QString( "C_OpenSession( SLOT_ID = %1, FLAGS = %2, APPLICATION_PTR = @0x%3, NOTIFY = @0x%4, SESSION_HANDLE_PTR = @0x%5 )")
                .arg(slotID).arg(flags).arg((quintptr)pApplication).arg((quintptr)Notify).arg((quintptr) phSession );
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

    strIn = QString( "C_CloseSession( SESSION_HANDLE = %1 )").arg( hSession );
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

    strIn = QString( "C_CloseAllSessions( SLOT_ID = %1 )").arg( slotID );
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

    strIn = QString( "C_Login( SESSION_HANDLE = %1, USER_TYPE = %2, Pin = %3, PinLen = %4 )" )
                .arg( hSession).arg( userType ).arg( (char *)pPin ).arg( ulPinLen );
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

    strIn = QString( "C_Logout( SESSION_HANDLE = %1 )").arg( hSession );
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

    strIn = QString( "C_GenerateKeyPair( SESSION_HANDLE = %1, MECHANISM_PTR = @0x%2, "
                   "PUBLIC_KEY_TEMPLATE_PTR = @0x%3 PUBLIC_KEY_ATTRIBUTE_COUNT = %4, "
                   "PRIVATE_KEY_TEMPLATE_PTR = @0x%5 PRIVATE_KEY_ATTRIBUTE_COUNT = %6, "
                   "OBJECT_HANDL_PTR = @0x%7, OBJECT_HANDL_PTR = @0x%8 )")
                .arg(hSession).arg((quintptr)pMechanism).arg((quintptr) pPubTemplate).arg(ulPubTemplateCnt)
                .arg((quintptr) pPriTemplate).arg( ulPriTemplateCnt).arg((quintptr) phPubKey).arg((quintptr) phPriKey );

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

    strIn = QString( "C_GenerateKey( SESSION_HANDLE = %1, MECHANISM_PTR = @0x%2, KEY_TEMPATE_PTR = @0x%3, KEY_ATTRIBUTE_COUNT = %4, OBJECT_HANDL_PTR = @0x%5 )")
                .arg(hSession).arg((quintptr) pMechanism).arg((quintptr) pTemplate).arg( ulTemplateCnt ).arg((quintptr) phKey );
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

    strIn = QString( "C_CreateObject( SESSION_HANDLE = %1, TEMPLATE_PTR = @0x%2 ATTRIBTE_COUNT = %3, OBJECT_HANDL_PTR = @0x%4 )")
                .arg(hSession).arg((quintptr) pTemplate).arg( ulTemplateCnt ).arg((quintptr) phObject );
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

    strIn = QString( "C_DestroyObject( SESSION_HANDLE = %1, OBJECT_HANDLE = %2 )").arg( hSession ).arg( hObject );
    manApplet->dlog( strIn );

    logResult( "C_DestroyObject", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::CopyObject( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_CopyObject( hSession, hObject, pTemplate, ulCount, phNewObject );
    ms = timer.elapsed();

    strIn = QString( "C_CopyObject( SESSION_HANDLE = %1, OBJECT_HANDLE = %2, TEMPLATE = @0x%3 ATTRIBUTE_COUNT = %4, OBJECT_HANDLE_PTR = @0x%5 )")
                .arg(hSession).arg( hObject).arg((quintptr) pTemplate).arg( ulCount ).arg((quintptr) phNewObject );
    manApplet->dlog( strIn );

    logTemplate( pTemplate, ulCount );

    logResult( "C_DeriveKey", rv, ms );

    if( rv == CKR_OK )
    {
        manApplet->dlog( QString( "New Object Handler : %1").arg( *phNewObject ));
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

    strIn = QString( "C_DigestInit( SESSION_HANDLE = %1, MECHANISM_PTR = @0x%2 )").arg( hSession ).arg((quintptr) pMechanism );
    manApplet->dlog( strIn );

    logResult( "C_DigestInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::DigestUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, bool bLog )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_DigestUpdate( hSession, pPart, ulPartLen );
    ms = timer.elapsed();

    if( bLog == false ) return rv;

    strIn = QString( "C_DigestUpdate( SESSION_HANDLE = %1, PART_PTR = @0x%2, PART_LEN = %3 )")
                .arg(hSession).arg((quintptr) pPart).arg( ulPartLen );
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

    strIn = QString( "C_DigestKey( SESSION_HANDLE = %1, OBJECT_HANDLE = %2 )")
                .arg( hSession ).arg( hKey );
    manApplet->dlog( strIn );



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

    strIn = QString( "C_DigestFinal( SESSION_HANDLE = %1, DIGEST_PTR = @0x%2 DIGEST_LEN_PTR = @0x%3")
                .arg(hSession).arg((quintptr) pDigest).arg((quintptr) pulDigestLen );
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

    strIn = QString( "C_Digest( SESSION_HANDLE = %1, DATA_PTR = @0x%2, DATA_LEN = %3, DIGEST_PTR = @0x%4, DIGEST_LEN_PTR = @0x%5 )")
                .arg(hSession).arg((quintptr) pData).arg( ulDataLen ).arg((quintptr) pDigest).arg((quintptr) pulDigestLen );
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

    strIn = QString( "C_SignInit( SESSION_HANDLE = %1, MECHANISM_PTR = @0x%2, OBJECT_HANDLE = %3 )")
                .arg( hSession ).arg((quintptr) pMechanism).arg( hKey );
    manApplet->dlog( strIn );

    logResult( "C_SignInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::SignUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, bool bLog )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_SignUpdate( hSession, pPart, ulPartLen );
    ms = timer.elapsed();

    if( bLog == false ) return rv;

    strIn = QString( "C_SignUpdate( SESSION_HANDLE = %1, PART_PTR = @0x%2, PART_LEN = %3 )")
                .arg(hSession).arg((quintptr) pPart).arg( ulPartLen );
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

    strIn = QString( "C_SignFinal( SESSION_HANDLE = %1, SIGN_PTR = @0x%2, SIGN_LEN_PTR = @0x%3 )")
                .arg( hSession ).arg((quintptr) pSign).arg((quintptr) pulSignLen );
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

    strIn = QString( "C_Sign( SESSION_HANDLE = %1, DATA_PTR = @0x%2, DATA_LEN = %3, SIGN_PTR = @0x%4, SIGN_LEN_PTR = @0x%5 )")
                .arg(hSession).arg((quintptr) pData).arg( ulDataLen).arg((quintptr) pSign).arg((quintptr) pulSignLen );
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

    strIn = QString( "C_SignRecoverInit( SESSION_HANDLE = %1, MECHANISM_PTR = @0x%2, OBJECT_HANDLE = %3 )")
                .arg(hSession).arg((quintptr) pMechanism).arg( hKey );
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

    strIn = QString( "C_SignRecover( SESSION_HANDLE = %1, DATA_PTR = @0x%2, DATA_LEN = %3, SIGN_PTR = @0x%4, SIGN_LEN_PTR = @0x%5 )")
                .arg( hSession ).arg((quintptr) pData ).arg( ulDataLen ).arg((quintptr) pSign ).arg((quintptr) pulSignLen );
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

    strIn = QString( "C_VerifyInit( SESSION_HANDLE = %1, MECHANISM_PTR = @0x%2, OBJECT_HANDLE = %3 )")
                .arg(hSession).arg((quintptr) pMechanism).arg( hKey );
    manApplet->dlog( strIn );

    logResult( "C_VerifyInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::VerifyUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, bool bLog )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_VerifyUpdate( hSession, pPart, ulPartLen );
    ms = timer.elapsed();

    if( bLog == false ) return rv;

    strIn = QString( "C_VerifyUpdate( SESSION_HANDLE = %1, PART_PTR = @0x%2, PART_LEN = %3 )")
                .arg(hSession).arg((quintptr) pPart).arg( ulPartLen );
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

    strIn = QString( "C_VerifyFinal( SESSION_HANDLE = %1, SIGN_PTR = @0x%2, SIGN_LEN = %3 )")
                .arg(hSession).arg((quintptr) pSign).arg( ulSignLen );
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

    strIn = QString( "C_Verify( SESSION_HANDLE = %1, DATA_PTR = @0x%2, DATA_LEN = %3, SIGN_PTR = @0x%4, SIGN_LEN = %5 )")
                .arg(hSession).arg((quintptr) pData).arg( ulDataLen ).arg((quintptr) pSign).arg( ulSignLen );
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

    strIn = QString( "C_VerifyRecoverInit( SESSION_HANDLE = %1, MECHANISM_PTR = @0x%2, OBJECT_HANDLE = %3 )")
                .arg(hSession).arg((quintptr) pMechanism).arg( hKey );
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

    strIn = QString( "C_VerifyRecover( SESSION_HANDLE = %1, SIGN_PTR = @0x%2, SIGN_LEN = %3, DATA_PTR = @0x%4, DATA_LEN_PTR = @0x%5 )")
                .arg(hSession).arg((quintptr) pSign).arg( ulSignLen ).arg((quintptr) pData).arg((quintptr) pulDataLen );
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

    strIn = QString( "C_EncryptInit( SESSION_HANDLE = %1, MECHANISM_PTR = @0x%2, OBJECT_HANDLE = %3 )")
                .arg(hSession).arg((quintptr) pMechanism).arg( hKey );
    manApplet->dlog( strIn );

    logResult( "C_EncryptInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::EncryptUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncPart, CK_ULONG_PTR pulEncPartLen, bool bLog )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_EncryptUpdate( hSession, pPart, ulPartLen, pEncPart, pulEncPartLen );
    ms = timer.elapsed();

    if( bLog == false ) return rv;

    strIn = QString( "C_EncryptUpdate( SESSION_HANDLE = %1, PART_PTR = @0x%2, PART_LEN = %3, ENC_PART_PTR = @0x%4, ENC_PART_LEN_PTR = @0x%5 )")
                .arg(hSession).arg((quintptr) pPart).arg( ulPartLen).arg((quintptr) pEncPart).arg((quintptr) pulEncPartLen );
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

    strIn = QString( "C_EncryptFinal( SESSION_HANDLE = %1, LAST_ENC_PART_PTR = %0x%2, LAST_ENC_PART_LEN_PTR = %3 )")
                .arg(hSession).arg((quintptr) pLastEncPart).arg((quintptr) pulLastEncPartLen );
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

    strIn = QString( "C_Encrypt( SESSION_HANDLE = %1, DATA_PTR = @0x%2, DATA_LEN = %3, ENC_DATA_PTR = @0x%4, ENC_DATA_LEN_PTR = @0x%5 )")
                .arg(hSession).arg((quintptr) pData ).arg( ulDataLen ).arg((quintptr) pEncData).arg((quintptr) pulEncDataLen );
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

    strIn = QString( "C_DecryptInit( SESSION_HANDLE = %1, MECHANISM_PTR = @0x%2, OBJECT_HANDLE = %3 )")
                .arg(hSession).arg((quintptr) pMechanism).arg( hKey );
    manApplet->dlog( strIn );

    logResult( "C_DecryptInit", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::DecryptUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncPart, CK_ULONG ulEncPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen, bool bLog )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_DecryptUpdate( hSession, pEncPart, ulEncPartLen, pPart, pulPartLen );
    ms = timer.elapsed();

    if( bLog == false ) return rv;

    strIn = QString( "C_DecryptUpdate( SESSION_HANDLE = %1, ENC_PART_PTR = @0x%2, ENC_PART_LEN = %3, PART_PTR = @0x%4, PART_LEN_PTR = @0x%5 )")
                .arg(hSession).arg((quintptr) pEncPart).arg( ulEncPartLen ).arg((quintptr) pPart).arg((quintptr) pulPartLen );
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

    strIn = QString( "C_DecryptFinal( SESSION_HANDLE = %1, LAST_PART_PTR = @0x%2, LAST_PART_LEN_PTR = %3 )")
                .arg(hSession).arg((quintptr) pLastPart).arg((quintptr) pulLastPartLen );
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

    strIn = QString( "C_Decrypt( SESSION_HANDLE = %1, ENC_DATA_PTR = @0x%2, ENC_DATA_LEN = %3, DATA_PTR = @0x%4, DATA_LEN_PTR = @0x%5 )")
                .arg(hSession).arg((quintptr) pEncData).arg( ulEncDataLen ).arg((quintptr) pData).arg((quintptr) pulDataLen );
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

    strIn = QString( "C_InitPIN( SESSION_HANDLE = %1, PIN_PTR = @0x%2, PIN_LEN = %3 )")
                .arg(hSession).arg((quintptr) pPin).arg( ulPinLen );
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

    strIn = QString( "C_SetPIN( SESSION_HANDLE = %1, OLD_PIN_PTR = @0x%2, OLD_PIN_LEN = %3, NEW_PIN_PTR = @0x%4, NEW_PIN_LEN = %5 )")
                .arg(hSession).arg((quintptr) pOldPin).arg( ulOldLen).arg((quintptr) pNewPin ).arg( ulNewLen );
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

    strIn = QString( "C_InitToken( SLOT_ID = %1, PIN_PTR = @0x%2, PIN_LEN = %3, LABEL_PTR = @0x%4")
                .arg(slotID)
                .arg((quintptr)pPin)
                .arg(ulPinLen)
                .arg((quintptr)pLabel );
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

    strIn = QString( "C_SeedRandom( SESSION_HANDLE = %1, SEED_PTR = @0x%2, SEED_LEN = %3 )")
                .arg(hSession).arg((quintptr) pSeed).arg( ulSeedLen );
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

    strIn = QString( "C_GenerateRandom( SESSION_HANDLE = %1, RANDOM_DATA_PTR = @0x%2, RANDOM_DATA_LEN = %3 )")
                .arg(hSession).arg((quintptr) pRandomData).arg( ulRandomLen );
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

    strIn = QString( "C_GetOperationState( SESSION_HANDLE = %1, OperationState_ptr = @0x%2, OperationStateLen = @0x%3 )")
                .arg(hSession).arg((quintptr) pOperationState).arg((quintptr) pulOperationStateLen );
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

    strIn = QString( "C_GetOperationState( SESSION_HANDLE = %1, OperationState_ptr = @0x%2, OperationStateLen = %3, EncryptKeyHandle = %4, AuthenticationKeyHandle = %5 )")
                .arg(hSession).arg((quintptr) pOperationState).arg( ulOperationStateLen ).arg( hEncryptionKey ).arg( hAuthenticationKey );
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

    strIn = QString( "C_DeriveKey( SESSION_HANDLE = %1, MECHANISM_PTR = @0x%2, OBJECT_HANDLE = %3, TEMPLATE = @0x%4 ATTRIBUTE_COUNT = %5, OBJECT_HANDLE_PTR = @0x%6 )")
                .arg(hSession).arg((quintptr) pMechanism).arg( hBaseKey ).arg((quintptr) pTemplate ).arg( ulTemplateCnt ).arg((quintptr) phKey );
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

    strIn = QString( "C_WrapKey( SESSION_HANDLE = %1, MECHANISM_PTR = @0x%2, OBJECT_HANDLE = %3, OBJECT_HANDLE = %4, WRAPPED_KEY_PTR = @0x%5, WRAPPED_KEY_LEN_PTR = @0x%6 )")
                .arg(hSession).arg((quintptr) pMechanism).arg( hWrappingKey ).arg( hKey ).arg((quintptr) pWrappedKey).arg((quintptr) pulWrappedKeyLen );
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

    strIn = QString( "C_UnwrapKey( SESSION_HANDLE = %1, MECHANISM_PTR = @0x%2, OBJECT_HANDLE = %3, WRAPPED_KEY_PTR = @0x%4, WRAPPED_KEY_LEN = %5, TEMPLATE = @0x%6, ATTRIBUTE_COUNT = %7, OBJECT_HANDLE_PTR = @0x%8 )")
                .arg(hSession).arg((quintptr) pMechanism).arg( hUnwrappingKey ).arg((quintptr) pWrappedKey).arg( ulWrappedKeyLen).arg((quintptr) pTemplate).arg( ulTemplateCnt ).arg((quintptr) phKey );
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

    strIn = QString( "C_WaitForSlotEvent( FLAGS = %1, SLOT_ID_PTR = @0x%2, RESERVER = @0x%3 )")
                .arg(uFlags).arg((quintptr) pSlot).arg((quintptr) pReserved );
    manApplet->dlog( strIn );

    logResult( "C_WaitForSlotEvent", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::GetFunctionStatus( CK_SESSION_HANDLE hSession )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_GetFunctionStatus( hSession );
    ms = timer.elapsed();

    strIn = QString( "C_GetFunctionStatus( SESSION_HANDLE = %1 )").arg( hSession );
    manApplet->dlog( strIn );

    logResult( "C_GetFunctionStatus", rv, ms );

    if( rv == CKR_OK )
    {

    }

    return rv;
}

int CryptokiAPI::CancelFunction( CK_SESSION_HANDLE hSession )
{
    int rv = 0;
    qint64 ms = 0;
    QElapsedTimer timer;
    QString strIn;

    timer.start();
    rv = p11_ctx_->p11FuncList->C_CancelFunction( hSession );
    ms = timer.elapsed();

    strIn = QString( "C_CancelFunction( SESSION_HANDLE = %1 )").arg( hSession );
    manApplet->dlog( strIn );

    logResult( "C_CancelFunction", rv, ms );

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

long CryptokiAPI::getHandle( CK_SESSION_HANDLE hSession, CK_OBJECT_CLASS objClass, const BIN *pID )
{
    int rv;

    CK_ATTRIBUTE sTemplate[2];
    long uCount = 0;

    CK_OBJECT_HANDLE hObjects = -1;
    CK_ULONG uObjCnt = 0;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_ID;
    sTemplate[uCount].pValue = pID->pVal;
    sTemplate[uCount].ulValueLen = pID->nLen;
    uCount++;


    rv = FindObjectsInit( hSession, sTemplate, uCount );
    if( rv != CKR_OK ) goto end;

    rv = FindObjects( hSession, &hObjects, 1, &uObjCnt );
    if( rv != CKR_OK ) goto end;

    rv = FindObjectsFinal( hSession );
    if( rv != CKR_OK ) goto end;

end :

    return hObjects;
}

const QString CryptokiAPI::getLabel( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObj )
{
    int rv = 0;
    QString strLabel;

    BIN binLabel = {0,0};
    char *pLabel = NULL;

    rv = GetAttributeValue2( hSession, hObj, CKA_LABEL, &binLabel );
    if( rv == CKR_OK )
    {
        JS_BIN_string( &binLabel, &pLabel );
        if( pLabel )
        {
            strLabel = pLabel;
            JS_free( pLabel );
        }
    }

    return strLabel;
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
