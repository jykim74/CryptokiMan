#include "p11_work.h"
#include "js_pki.h"
#include "js_pki_key.h"
#include "js_pki_tools.h"
#include "js_pki_eddsa.h"

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

int getECPublicKey( CryptokiAPI *pAPI, long hSession, long hObject, BIN *pPubKey )
{
    int ret = 1;
    BIN binParam = {0,0};
    BIN binPoint = {0,0};
    JECKeyVal sECKey;
    char sTextOID[1024];
    QString strHexX;
    QString strHexY;
    int nPubLen = 0;

    memset( &sECKey, 0x00, sizeof(sECKey));

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_EC_PARAMS, &binParam );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_EC_POINT, &binPoint );
    if( ret != CKR_OK ) goto end;

    nPubLen = (binPoint.nLen -1) / 2;

    strHexX = getHexString( &binPoint.pVal[1], nPubLen );
    strHexY = getHexString( &binPoint.pVal[1+nPubLen], nPubLen );

    JS_PKI_getStringFromOID( &binParam, sTextOID );

    JS_PKI_setECKeyVal( &sECKey, sTextOID, strHexX.toStdString().c_str(), strHexY.toStdString().c_str(), NULL );

    ret = JS_PKI_encodeECPublicKey( &sECKey, pPubKey );

end :
    JS_BIN_reset( &binParam );
    JS_BIN_reset( &binPoint );
    JS_PKI_resetECKeyVal( &sECKey );

    return ret;
}

int getDSAPublicKey( CryptokiAPI *pAPI, long hSession, long hObject, BIN *pPubKey )
{
    int ret = 0;
    BIN binP = {0,0};
    BIN binQ = {0,0};
    BIN binG = {0,0};
    BIN binVal = {0,0};

    JDSAKeyVal sDSAKey;

    memset( &sDSAKey, 0x00, sizeof(&sDSAKey));

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_PRIME, &binP );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_SUBPRIME, &binQ );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_BASE, &binG );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_VALUE, &binVal );
    if( ret != 0 ) goto end;

    JS_PKI_setDSAKeyVal( &sDSAKey,
                        getHexString( &binG ).toStdString().c_str(),
                        getHexString( &binP ).toStdString().c_str(),
                        getHexString( &binQ ).toStdString().c_str(),
                        getHexString( &binVal ).toStdString().c_str(),
                        NULL );

    ret = JS_PKI_encodeDSAPublicKey( &sDSAKey, pPubKey );

end :
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binG );

    return ret;
}

int getEDPublicKey( CryptokiAPI *pAPI, long hSession, long hObject, BIN *pPubKey )
{
    int ret = -1;
    BIN binPoint = {0,0};
    BIN binParam = {0,0};
    BIN binPub = {0,0};

    int nKeyType = JS_PKI_KEY_TYPE_ED25519;

    if( binPoint.nLen != ( 32 + 2 ) )
        nKeyType = JS_PKI_KEY_TYPE_ED448;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_EC_POINT, &binPoint );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_EC_PARAMS, &binParam );
    if( ret != CKR_OK ) goto end;


    JS_BIN_set( &binPub, &binPoint.pVal[2], binPoint.nLen - 2 );
    ret = JS_PKI_encodeRawPublicKeyValue( nKeyType, &binPub, pPubKey );

end :
    JS_BIN_reset( &binPoint );
    JS_BIN_reset( &binParam );
    JS_BIN_reset( &binPub );

    return ret;
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
