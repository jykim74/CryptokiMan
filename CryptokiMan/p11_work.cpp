#include "p11_work.h"
#include "js_pki.h"
#include "js_pki_key.h"

#include "common.h"

int getRSAPublicKey( CryptokiAPI *pAPI, long hSesson, long hObject, BIN *pPubKey )
{
    int ret = 0;
    BIN binPubExp = {0,0};
    BIN binModules = {0,0};

    JRSAKeyVal sRSAKey;

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));

    ret = pAPI->GetAttributeValue2( hSesson, hObject, CKA_PUBLIC_EXPONENT, &binPubExp );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSesson, hObject, CKA_MODULUS, &binModules );
    if( ret != CKR_OK ) goto end;

    JS_PKI_setRSAKeyVal( &sRSAKey,
                        getHexString( &binModules ).toStdString().c_str(),
                        getHexString( &binPubExp ).toStdString().c_str(),
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL );

    ret = JS_PKI_encodeRSAPublicKey( &sRSAKey, pPubKey );

end :
    JS_BIN_reset( &binPubExp );
    JS_BIN_reset( &binModules );
    JS_PKI_resetRSAKeyVal( &sRSAKey );

    return ret;
}

int getECPublicKey( CryptokiAPI *pAPI, long hSesson, long hObject, BIN *pPubKey )
{
    return 0;
}

int getDSAPublicKey( CryptokiAPI *pAPI, long hSesson, long hObject, BIN *pPubKey )
{
    return 0;
}

int getEDPublicKey( CryptokiAPI *pAPI, long hSesson, long hObject, BIN *pPubKey )
{
    return 0;
}

int getPublicKey( CryptokiAPI *pAPI, long hSession, long hObject, BIN *pPubKey )
{
    int ret = 0;
    BIN binVal = {0,0};
    long uKeyType = 0;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_KEY_TYPE, &binVal );
    if( ret != 0 ) goto end;

    memcpy( &uKeyType, binVal.pVal, binVal.nLen );

    if( uKeyType == CKK_RSA )
        ret = getRSAPublicKey( pAPI, hSession, hObject, pPubKey );
    else if( uKeyType == CKK_EC )
        ret = getECPublicKey( pAPI, hSession, hObject, pPubKey );
    else if( uKeyType == CKK_DSA )
        ret = getDSAPublicKey( pAPI, hSession, hObject, pPubKey );
    else if( uKeyType == CKK_EC_EDWARDS )
        ret = getEDPublicKey( pAPI, hSession, hObject, pPubKey );
    else
        ret = -1;

end :
    JS_BIN_reset( &binVal );

    return ret;
}
