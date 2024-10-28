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

    nPubLen = (binPoint.nLen - 3) / 2;

    strHexX = getHexString( &binPoint.pVal[3], nPubLen );
    strHexY = getHexString( &binPoint.pVal[3+nPubLen], nPubLen );

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

    memset( &sDSAKey, 0x00, sizeof(sDSAKey));

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
    JS_BIN_reset( &binVal );
    JS_PKI_resetDSAKeyVal( &sDSAKey );

    return ret;
}

int getEDPublicKey( CryptokiAPI *pAPI, long hSession, long hObject, BIN *pPubKey )
{
    int ret = -1;
    BIN binPoint = {0,0};
    BIN binParam = {0,0};
    BIN binPub = {0,0};

    int nKeyType = JS_PKI_KEY_TYPE_ED25519;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_EC_POINT, &binPoint );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_EC_PARAMS, &binParam );
    if( ret != CKR_OK ) goto end;

    if( binPoint.nLen != ( 32 + 2 ) )
        nKeyType = JS_PKI_KEY_TYPE_ED448;


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


int getRSAPrivateKey( CryptokiAPI *pAPI, long hSession, long hObject, BIN *pPriKey )
{
    int ret = 0;
    BIN binN = {0,0};
    BIN binE = {0,0};
    BIN binD = {0,0};
    BIN binP = {0,0};
    BIN binQ = {0,0};
    BIN binDMP1 = {0,0};
    BIN binDMQ1 = {0,0};
    BIN binIQMP = {0,0};

    JRSAKeyVal sRSAKey;

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_PUBLIC_EXPONENT, &binE );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_MODULUS, &binN );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_PRIVATE_EXPONENT, &binD );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_PRIME_1, &binP );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_PRIME_2, &binQ );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_EXPONENT_1, &binDMP1 );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_EXPONENT_2, &binDMQ1 );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_COEFFICIENT, &binIQMP );
    if( ret != CKR_OK ) goto end;

    JS_PKI_setRSAKeyVal( &sRSAKey,
                        getHexString( &binN ).toStdString().c_str(),
                        getHexString( &binE ).toStdString().c_str(),
                        getHexString( &binD ).toStdString().c_str(),
                        getHexString( &binP ).toStdString().c_str(),
                        getHexString( &binQ ).toStdString().c_str(),
                        getHexString( &binDMP1 ).toStdString().c_str(),
                        getHexString( &binDMQ1 ).toStdString().c_str(),
                        getHexString( &binIQMP ).toStdString().c_str() );

    ret = JS_PKI_encodeRSAPrivateKey( &sRSAKey, pPriKey );

end :
    JS_BIN_reset( &binN );
    JS_BIN_reset( &binE );
    JS_BIN_reset( &binD );
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binDMP1 );
    JS_BIN_reset( &binDMQ1 );
    JS_BIN_reset( &binIQMP );

    JS_PKI_resetRSAKeyVal( &sRSAKey );

    return ret;
}

int getECPrivateKey( CryptokiAPI *pAPI, long hSession, long hObject, BIN *pPriKey )
{
    int ret = 1;
    BIN binParam = {0,0};
    BIN binValue = {0,0};
    JECKeyVal sECKey;
    char sTextOID[1024];
    memset( &sECKey, 0x00, sizeof(sECKey));

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_EC_PARAMS, &binParam );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_VALUE, &binValue );
    if( ret != CKR_OK ) goto end;


    JS_PKI_getStringFromOID( &binParam, sTextOID );

    JS_PKI_setECKeyVal( &sECKey, sTextOID, NULL, NULL, getHexString( &binValue ).toStdString().c_str() );

    ret = JS_PKI_encodeECPrivateKey( &sECKey, pPriKey );

end :
    JS_BIN_reset( &binParam );
    JS_BIN_reset( &binValue );
    JS_PKI_resetECKeyVal( &sECKey );

    return ret;
}

int getDSAPrivateKey( CryptokiAPI *pAPI, long hSession, long hObject, BIN *pPriKey )
{
    int ret = 0;
    BIN binP = {0,0};
    BIN binQ = {0,0};
    BIN binG = {0,0};
    BIN binVal = {0,0};

    JDSAKeyVal sDSAKey;

    memset( &sDSAKey, 0x00, sizeof(sDSAKey));

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
                        NULL,
                        getHexString( &binVal ).toStdString().c_str() );

    ret = JS_PKI_encodeDSAPrivateKey( &sDSAKey, pPriKey );

end :
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binG );
    JS_PKI_resetDSAKeyVal( &sDSAKey );

    return ret;
}

int getEDPrivateKey( CryptokiAPI *pAPI, long hSession, long hObject, BIN *pPriKey )
{
    int ret = -1;
    BIN binParam = {0,0};
    BIN binValue = {0,0};
    BIN binPoint = {0,0};

    JRawKeyVal sRawKey;
    QString strName = "ED25519";

    int nKeyType = JS_PKI_KEY_TYPE_ED25519;

    memset( &sRawKey, 0x00, sizeof(sRawKey));


    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_EC_PARAMS, &binParam );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_VALUE, &binValue );
    if( ret != CKR_OK ) goto end;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_EC_POINT, &binPoint );
//    if( ret != CKR_OK ) goto end;


    if( binValue.nLen != 32 )
        strName = "ED448";

    JS_PKI_setRawKeyVal( &sRawKey,
                        ( binPoint.nLen > 0 ) ? getHexString( &binPoint ).toStdString().c_str() : NULL,
                        getHexString( &binValue ).toStdString().c_str(),
                        strName.toStdString().c_str() );

    ret = JS_PKI_encodeRawPrivateKey( &sRawKey, pPriKey );

end :
    JS_BIN_reset( &binParam );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binPoint );
    JS_PKI_resetRawKeyVal( &sRawKey );

    return ret;
}


int getPrivateKey( CryptokiAPI *pAPI, long hSession, long hObject, BIN *pPriKey )
{
    int ret = 0;
    BIN binVal = {0,0};
    long uKeyType = 0;

    ret = pAPI->GetAttributeValue2( hSession, hObject, CKA_KEY_TYPE, &binVal );
    if( ret != 0 ) goto end;

    memcpy( &uKeyType, binVal.pVal, binVal.nLen );

    if( uKeyType == CKK_RSA )
        ret = getRSAPrivateKey( pAPI, hSession, hObject, pPriKey );
    else if( uKeyType == CKK_EC )
        ret = getECPrivateKey( pAPI, hSession, hObject, pPriKey );
    else if( uKeyType == CKK_DSA )
        ret = getDSAPrivateKey( pAPI, hSession, hObject, pPriKey );
    else if( uKeyType == CKK_EC_EDWARDS )
        ret = getEDPrivateKey( pAPI, hSession, hObject, pPriKey );
    else
        ret = -1;

end :
    JS_BIN_reset( &binVal );

    return ret;
}
