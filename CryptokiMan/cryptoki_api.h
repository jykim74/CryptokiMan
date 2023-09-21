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
    CK_SESSION_HANDLE getSessionHandle();
    JP11_CTX* getCTX() { return p11_ctx_; };

    bool isInit() { return init_; };

    int openLibrary( const QString strPath );
    int unloadLibrary();
    int Initialize( void *pReserved );
    int Finalize( void *pReserved );
    int GetSlotList( CK_BBOOL bVal, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pSlotCnt );
    int GetSlotList2( CK_BBOOL bVal, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pSlotCnt );
    int GetInfo( CK_INFO_PTR pInfo );
    int GetSlotInfo( CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pSlotInfo );
    int GetTokenInfo( CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pTokenInfo );
    int GetMechanismList( CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechList, CK_ULONG *puMechCount );
    int GetMechanismInfo( CK_SLOT_ID slotID, CK_MECHANISM_TYPE iMechType, CK_MECHANISM_INFO_PTR pInfo );
    int GetSessionInfo( CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pSessionInfo );
    int FindObjectsInit( CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG uCount );
    int FindObjects( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG uMaxObjCount, CK_ULONG_PTR puObjCount );
    int FindObjectsFinal( CK_SESSION_HANDLE hSession );
    int GetObjectSize( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR puSize );
    int GetAttributeValue( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pAttribute, CK_ULONG uAttributeCnt );
    int GetAttributeValue2( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_TYPE attrType, BIN *pBinVal );
    int SetAttributeValue( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pAttribute, CK_ULONG uAttributeCnt );
    int SetAttributeValue2( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_TYPE attrType, BIN *pBinVal );

    int OpenSession( CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession );
    int CloseSession( CK_SESSION_HANDLE hSession );
    int CloseAllSession( CK_SLOT_ID slotID );
    int Login( CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen );
    int Logout( CK_SESSION_HANDLE hSession );
    int GenerateKeyPair(
            CK_SESSION_HANDLE hSession,
            CK_MECHANISM_PTR pMechanism,
            CK_ATTRIBUTE_PTR pPubTemplate,
            CK_ULONG ulPubTemplateCnt,
            CK_ATTRIBUTE_PTR pPriTemplate,
            CK_ULONG ulPriTemplateCnt,
            CK_OBJECT_HANDLE_PTR phPubKey,
            CK_OBJECT_HANDLE_PTR phPriKey );

    int GenerateKey(
            CK_SESSION_HANDLE hSession,
            CK_MECHANISM_PTR pMechanism,
            CK_ATTRIBUTE_PTR pTemplate,
            CK_ULONG ulTemplateCnt,
            CK_OBJECT_HANDLE_PTR phKey );

    int CreateObject(
            CK_SESSION_HANDLE hSession,
            CK_ATTRIBUTE_PTR pTemplate,
            CK_ULONG ulTemplateCnt,
            CK_OBJECT_HANDLE_PTR phObject );

    int DestroyObject( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject );
    int CopyObject( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject );

    int DigestInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism );
    int DigestUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen );
    int DigestKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey );
    int DigestFinal( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen );
    int Digest( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen );

    int SignInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey );
    int SignUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen );
    int SignFinal( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSign, CK_ULONG_PTR pulSignLen );
    int Sign( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSign, CK_ULONG_PTR pulSignLen );

    int SignRecoverInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey );
    int SignRecover( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSign, CK_ULONG_PTR pulSignLen );

    int VerifyInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey );
    int VerifyUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen );
    int VerifyFinal( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSign, CK_ULONG ulSignLen );
    int Verify( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSign, CK_ULONG ulSignLen );

    int VerifyRecoverInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey );
    int VerifyRecover( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSign, CK_ULONG ulSignLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen );

    int EncryptInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey );
    int EncryptUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncPart, CK_ULONG_PTR pulEncPartLen );
    int EncryptFinal( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncPart, CK_ULONG_PTR pulLastEncPartLen );
    int Encrypt( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncData, CK_ULONG_PTR pulEncDataLen );

    int DecryptInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey );
    int DecryptUpdate( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncPart, CK_ULONG ulEncPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen );
    int DecryptFinal( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen );
    int Decrypt( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncData, CK_ULONG ulEncDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen );

    int InitPIN( CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen );
    int SetPIN( CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen );
    int InitToken( CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel );

    int SeedRandom( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen );
    int GenerateRandom( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen );

    int GetOperationState( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen );
    int SetOperationState( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey );

    int DeriveKey( CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hBaseKey,
                   CK_ATTRIBUTE_PTR pTemplate,
                   CK_ULONG ulTemplateCnt,
                   CK_OBJECT_HANDLE_PTR phKey );

    int WrapKey( CK_SESSION_HANDLE hSession,
                 CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hWrappingKey,
                 CK_OBJECT_HANDLE hKey,
                 CK_BYTE_PTR pWrappedKey,
                 CK_ULONG_PTR pulWrappedKeyLen );

    int UnwrapKey( CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hUnwrappingKey,
                   CK_BYTE_PTR pWrappedKey,
                   CK_ULONG ulWrappedKeyLen,
                   CK_ATTRIBUTE_PTR pTemplate,
                   CK_ULONG ulTemplateCnt,
                   CK_OBJECT_HANDLE_PTR phKey );

    int WaitForSlotEvent( CK_FLAGS uFlags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved );

    QString getLastError();

private:
    void logResult( const QString strName, int rv, qint64 ms = -1 );
    void logTemplate( const CK_ATTRIBUTE sTemplate[], int nCount );

private:
    JP11_CTX       *p11_ctx_;
    bool            init_;
};

#endif // CRYPTOKIAPI_H
