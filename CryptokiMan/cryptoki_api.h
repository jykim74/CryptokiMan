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

private:
    void logResult( const QString strName, int rv, qint64 ms = -1 );
    void logTemplate( const CK_ATTRIBUTE sTemplate[], int nCount );

private:
    JP11_CTX       *p11_ctx_;
};

#endif // CRYPTOKIAPI_H
