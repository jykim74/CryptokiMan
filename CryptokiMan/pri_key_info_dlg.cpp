/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>

#include "js_bin.h"
#include "js_pki.h"
#include "js_pki_raw.h"
#include "js_pki_tools.h"
#include "js_pki_key.h"

#include "man_applet.h"
#include "pri_key_info_dlg.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "js_error.h"
#include "common.h"
#include "cryptoki_api.h"
#include "p11_work.h"


PriKeyInfoDlg::PriKeyInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    key_type_ = -1;
    session_ = 0;
    pub_handle_ = 0;
    pri_handle_ = 0;

    memset( &pri_key_, 0x00, sizeof(BIN));
    memset( &pub_key_, 0x00, sizeof(BIN));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mRSA_NText, SIGNAL(textChanged()), this, SLOT(changeRSA_N()));
    connect( mRSA_EText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_E(const QString&)));
    connect( mRSA_DText, SIGNAL(textChanged()), this, SLOT(changeRSA_D()));
    connect( mRSA_PText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_P(const QString&)));
    connect( mRSA_QText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_Q(const QString&)));
    connect( mRSA_DMP1Text, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_DMP1(const QString&)));
    connect( mRSA_DMQ1Text, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_DMQ1(const QString&)));
    connect( mRSA_IQMPText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_IQMP(const QString&)));

    connect( mECC_PubXText, SIGNAL(textChanged()), this, SLOT(changeECC_PubX()));
    connect( mECC_PubYText, SIGNAL(textChanged()), this, SLOT(changeECC_PubY()));
    connect( mECC_PrivateText, SIGNAL(textChanged()), this, SLOT(changeECC_Private()));

    connect( mDSA_GText, SIGNAL(textChanged()), this, SLOT(changeDSA_G()));
    connect( mDSA_PText, SIGNAL(textChanged()), this, SLOT(changeDSA_P()));
    connect( mDSA_QText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_Q(const QString&)));
    connect( mDSA_PublicText, SIGNAL(textChanged()), this, SLOT(changeDSA_Public()));
    connect( mDSA_PrivateText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_Private(const QString&)));

    connect( mEdDSA_RawPublicText, SIGNAL(textChanged()), this, SLOT(changeEdDSA_RawPublic()));
    connect( mEdDSA_RawPrivateText, SIGNAL(textChanged()), this, SLOT(changeEdDSA_RawPrivate()));
    connect( mCheckPubKeyBtn, SIGNAL(clicked()), this, SLOT(clickCheckPubKey()));

    initialize();
    mCloseBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    tabRSA->layout()->setSpacing(5);
    tabRSA->layout()->setMargin(5);
    tabECC->layout()->setSpacing(5);
    tabECC->layout()->setMargin(5);
    tabDSA->layout()->setSpacing(5);
    tabDSA->layout()->setMargin(5);
    tabEdDSA->layout()->setSpacing(5);
    tabEdDSA->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

PriKeyInfoDlg::~PriKeyInfoDlg()
{
    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );
}

void PriKeyInfoDlg::setInfo( const QString strInfo )
{
    mInfoLabel->setText( strInfo );
}

void PriKeyInfoDlg::initialize()
{
    mKeyTab->setTabEnabled(0, false);
    mKeyTab->setTabEnabled(1, false);
    mKeyTab->setTabEnabled(2, false);
    mKeyTab->setTabEnabled(3, false);
}

bool PriKeyInfoDlg::isChanged()
{
    if( key_type_ < 0 ) return true;

    if( key_type_ == JS_PKI_KEY_TYPE_RSA )
    {
        JRSAKeyVal sRSAKey;
        memset( &sRSAKey, 0x00, sizeof(sRSAKey));

        if( pri_key_.nLen > 0 )
            JS_PKI_getRSAKeyVal( &pri_key_, &sRSAKey );
        else
            JS_PKI_getRSAKeyValFromPub( &pub_key_, &sRSAKey );

        if( mRSA_EText->text().simplified().toUpper() != QString( "%1" ).arg( sRSAKey.pE ) )
            return true;

        if( mRSA_NText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sRSAKey.pN ) )
            return true;

        if( pri_key_.nLen > 0 )
        {
            if( mRSA_DText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sRSAKey.pD ) )
            {
                JS_PKI_resetRSAKeyVal( &sRSAKey );
                return true;
            }

            if( mRSA_DMP1Text->text().simplified().toUpper() != QString( "%1" ).arg( sRSAKey.pDMP1 ))
            {
                JS_PKI_resetRSAKeyVal( &sRSAKey );
                return true;
            }

            if( mRSA_DMQ1Text->text().simplified().toUpper() != QString( "%1" ).arg( sRSAKey.pDMQ1) )
            {
                JS_PKI_resetRSAKeyVal( &sRSAKey );
                return true;
            }

            if( mRSA_IQMPText->text().simplified().toUpper() != QString( "%1" ).arg( sRSAKey.pIQMP ))
            {
                JS_PKI_resetRSAKeyVal( &sRSAKey );
                return true;
            }
        }

        JS_PKI_resetRSAKeyVal( &sRSAKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ECDSA || key_type_ == JS_PKI_KEY_TYPE_SM2 )
    {
        JECKeyVal sECKey;
        memset( &sECKey, 0x00, sizeof(sECKey));

        if( pri_key_.nLen > 0 )
            JS_PKI_getECKeyVal( &pri_key_, &sECKey );
        else
            JS_PKI_getECKeyValFromPub( &pub_key_, &sECKey );

        if( mECC_PubXText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sECKey.pPubX ))
        {
            JS_PKI_resetECKeyVal( &sECKey );
            return true;
        }

        if( mECC_PubYText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sECKey.pPubY ))
        {
            JS_PKI_resetECKeyVal( &sECKey );
            return true;
        }

        if( pri_key_.nLen > 0 )
        {
            if( mECC_PrivateText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sECKey.pPrivate ))
            {
                JS_PKI_resetECKeyVal( &sECKey );
                return true;
            }
        }

        JS_PKI_resetECKeyVal( &sECKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_DSA )
    {
        JDSAKeyVal sDSAKey;
        memset( &sDSAKey, 0x00, sizeof(sDSAKey));

        if( pri_key_.nLen > 0 )
            JS_PKI_getDSAKeyVal( &pri_key_, &sDSAKey );
        else
            JS_PKI_getDSAKeyValFromPub( &pub_key_, &sDSAKey );

        if( mDSA_QText->text().simplified().toUpper() != QString( "%1" ).arg( sDSAKey.pQ ) )
        {
            JS_PKI_resetDSAKeyVal( &sDSAKey );
            return true;
        }

        if( mDSA_GText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sDSAKey.pG ))
        {
            JS_PKI_resetDSAKeyVal( &sDSAKey );
            return true;
        }

        if( mDSA_PText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sDSAKey.pP ))
        {
            JS_PKI_resetDSAKeyVal( &sDSAKey );
            return true;
        }

        if( mDSA_PublicText->toPlainText().simplified().toUpper() != QString("%1").arg( sDSAKey.pPublic ))
        {
            JS_PKI_resetDSAKeyVal( &sDSAKey );
            return true;
        }

        if( pri_key_.nLen > 0 )
        {
            if( mDSA_PrivateText->text().simplified().toUpper() != QString( "%1" ).arg( sDSAKey.pPrivate ))
            {
                JS_PKI_resetDSAKeyVal( &sDSAKey );
                return true;
            }
        }

        JS_PKI_resetDSAKeyVal( &sDSAKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_EDDSA )
    {
        JRawKeyVal sRawKey;
        memset( &sRawKey, 0x00, sizeof(sRawKey));

        if( pri_key_.nLen > 0 )
            JS_PKI_getRawKeyVal( &pri_key_, &sRawKey );
        else
            JS_PKI_getRawKeyValFromPub( &pub_key_, &sRawKey );

        if( mEdDSA_RawPublicText->toPlainText().simplified().toUpper() != QString("%1").arg( sRawKey.pPub ) )
        {
            JS_PKI_resetRawKeyVal( &sRawKey );
            return true;
        }

        if( pri_key_.nLen > 0 )
        {
            if( mEdDSA_RawPrivateText->toPlainText().simplified().toUpper() != QString("%1").arg( sRawKey.pPri ))
            {
                JS_PKI_resetRawKeyVal( &sRawKey );
                return true;
            }
        }

        JS_PKI_resetRawKeyVal( &sRawKey );
    }

    return false;
}

void PriKeyInfoDlg::showEvent(QShowEvent *event)
{

}

void PriKeyInfoDlg::setRSAKey( const BIN *pKey, bool bPri )
{
    int ret = 0;
    JRSAKeyVal  sRSAKey;

    if( pKey == NULL || pKey->nLen <= 0 ) return;

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));

    if( bPri == true )
        ret = JS_PKI_getRSAKeyVal( pKey, &sRSAKey );
    else
        ret = JS_PKI_getRSAKeyValFromPub( pKey, &sRSAKey );

    if( ret == 0 )
    {
        mRSA_NText->setPlainText( sRSAKey.pN );
        mRSA_EText->setText( sRSAKey.pE );
        mRSA_DText->setPlainText( sRSAKey.pD );
        mRSA_PText->setText( sRSAKey.pP );
        mRSA_QText->setText( sRSAKey.pQ );
        mRSA_DMP1Text->setText( sRSAKey.pDMP1 );
        mRSA_DMQ1Text->setText( sRSAKey.pDMQ1 );
        mRSA_IQMPText->setText( sRSAKey.pIQMP );
    }

    JS_PKI_resetRSAKeyVal( &sRSAKey );
}

void PriKeyInfoDlg::setECCKey( const BIN *pKey, bool bPri )
{
    int ret = 0;
    JECKeyVal sECKey;

    if( pKey == NULL || pKey->nLen <= 0 ) return;

    memset( &sECKey, 0x00, sizeof(sECKey));

    if( bPri == true )
        ret = JS_PKI_getECKeyVal( pKey, &sECKey );
    else
        ret = JS_PKI_getECKeyValFromPub( pKey, &sECKey );

    if( ret == 0 )
    {
        QString strSN = JS_PKI_getSNFromOID( sECKey.pCurveOID );
        mECC_CurveOIDText->setText( sECKey.pCurveOID );
        mECC_CurveSNText->setText( strSN );

        mECC_PubXText->setPlainText( sECKey.pPubX );
        mECC_PubYText->setPlainText( sECKey.pPubY );
        mECC_PrivateText->setPlainText( sECKey.pPrivate );
    }

    JS_PKI_resetECKeyVal( &sECKey );
}

void PriKeyInfoDlg::setDSAKey( const BIN *pKey, bool bPri )
{
    int ret = 0;
    JDSAKeyVal sDSAKey;

    if( pKey == NULL || pKey->nLen <= 0 ) return;

    memset( &sDSAKey, 0x00, sizeof(sDSAKey));

    if( bPri == true )
        ret = JS_PKI_getDSAKeyVal( pKey, &sDSAKey );
    else
        ret = JS_PKI_getDSAKeyValFromPub( pKey, &sDSAKey );

    if( ret == 0 )
    {
        mDSA_GText->setPlainText( sDSAKey.pG );
        mDSA_PText->setPlainText( sDSAKey.pP );
        mDSA_QText->setText( sDSAKey.pQ );
        mDSA_PublicText->setPlainText( sDSAKey.pPublic );
        mDSA_PrivateText->setText( sDSAKey.pPrivate );
    }

    JS_PKI_resetDSAKeyVal( &sDSAKey );
}

void PriKeyInfoDlg::setEdDSAKey( int nKeyType, const BIN *pKey, bool bPri )
{
    int ret = 0;
    JRawKeyVal sRawKeyVal;

    if( pKey == NULL || pKey->nLen <= 0 ) return;

    memset( &sRawKeyVal, 0x00, sizeof(sRawKeyVal));

    if( bPri == true )
        ret = JS_PKI_getRawKeyVal( pKey, &sRawKeyVal );
    else
        ret = JS_PKI_getRawKeyValFromPub( pKey, &sRawKeyVal );

    if( ret == 0 )
    {
        mEdDSA_NameText->setText( sRawKeyVal.pAlg );
        mEdDSA_ParamText->setText( sRawKeyVal.pParam );
        mEdDSA_RawPublicText->setPlainText( sRawKeyVal.pPub );
        mEdDSA_RawPrivateText->setPlainText( sRawKeyVal.pPri );
    }

    JS_PKI_resetRawKeyVal( &sRawKeyVal );
}

void PriKeyInfoDlg::setRSAKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, bool bPri )
{
    int ret = 0;
    BIN binVal = {0,0};

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    bool bVal = manApplet->settingsMgr()->displayValid();

    ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_PUBLIC_EXPONENT, &binVal );
    if( ret == CKR_OK )
    {
        mRSA_EText->setText( getHexString( &binVal ) );
        JS_BIN_reset( &binVal );
    }
    else
    {
        if( bVal == false )
            mRSA_EText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
    }

    ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_MODULUS, &binVal );
    if( ret == CKR_OK )
    {
        mRSA_NText->setPlainText( getHexString( &binVal ) );
        JS_BIN_reset( &binVal );
    }
    else
    {
        if( bVal == false )
            mRSA_NText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
    }

    if( bPri == true )
    {
        ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_PRIVATE_EXPONENT, &binVal );
        if( ret == CKR_OK )
        {
            mRSA_DText->setPlainText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            if( bVal == false )
                mRSA_DText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }

        ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_PRIME_1, &binVal );
        if( ret == CKR_OK )
        {
            mRSA_PText->setText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            if( bVal == false )
                mRSA_PText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }

        ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_PRIME_2, &binVal );
        if( ret == CKR_OK )
        {
            mRSA_QText->setText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            if( bVal == false )
                mRSA_QText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }

        ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_EXPONENT_1, &binVal );
        if( ret == CKR_OK )
        {
            mRSA_DMP1Text->setText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            if( bVal == false )
                mRSA_DMP1Text->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }

        ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_EXPONENT_2, &binVal );
        if( ret == CKR_OK )
        {
            mRSA_DMQ1Text->setText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            if( bVal == false )
                mRSA_DMQ1Text->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }

        ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_COEFFICIENT, &binVal );
        if( ret == CKR_OK )
        {
            mRSA_IQMPText->setText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            if( bVal == false )
                mRSA_IQMPText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }

    JS_BIN_reset( &binVal );
}

void PriKeyInfoDlg::setECCKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, bool bPri )
{
    int ret = 0;
    BIN binVal = {0,0};

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    bool bVal = manApplet->settingsMgr()->displayValid();

    char sTextOID[1024];

    ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_EC_PARAMS, &binVal );
    if( ret == CKR_OK )
    {
        JS_PKI_getStringFromOID( &binVal, sTextOID );
        JS_BIN_reset( &binVal );

        mECC_CurveOIDText->setText( sTextOID );
        mECC_CurveSNText->setText( JS_PKI_getSNFromOID( sTextOID ) );
    }
    else
    {
        if( bVal == false )
            mECC_CurveOIDText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
    }

    if( bPri == false )
    {
        ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_EC_POINT, &binVal );
        if( ret == CKR_OK )
        {
            int nPubLen = (binVal.nLen - 3) / 2;
            mECC_PubXText->setPlainText( getHexString( &binVal.pVal[3], nPubLen));
            mECC_PubYText->setPlainText( getHexString( &binVal.pVal[3 + nPubLen], nPubLen));

            JS_BIN_reset( &binVal );
        }
        else
        {
            if( bVal == false )
            {
                mECC_PubXText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
                mECC_PubYText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
            }
        }
    }
    else
    {
        ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_VALUE, &binVal );
        if( ret == CKR_OK )
        {
            mECC_PrivateText->setPlainText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            if( bVal == false )
                mECC_PrivateText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }

    JS_BIN_reset( &binVal );
}

void PriKeyInfoDlg::setDSAKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, bool bPri )
{
    int ret = 0;
    BIN binVal = {0,0};

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    bool bVal = manApplet->settingsMgr()->displayValid();

    ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_PRIME, &binVal );
    if( ret == CKR_OK )
    {
        mDSA_PText->setPlainText( getHexString( &binVal ) );
        JS_BIN_reset( &binVal );
    }
    else
    {
        if( bVal == false )
            mDSA_PText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
    }

    ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_SUBPRIME, &binVal );
    if( ret == CKR_OK )
    {
        mDSA_QText->setText( getHexString( &binVal ) );
        JS_BIN_reset( &binVal );
    }
    else
    {
        if( bVal == false )
            mDSA_QText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
    }

    ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_BASE, &binVal );
    if( ret == CKR_OK )
    {
        mDSA_GText->setPlainText( getHexString( &binVal ) );
        JS_BIN_reset( &binVal );
    }
    else
    {
        if( bVal == false )
            mDSA_GText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
    }

    if( bPri == true )
    {
        ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_VALUE, &binVal );
        if( ret == CKR_OK )
        {
            mDSA_PrivateText->setText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            if( bVal == false )
                mDSA_PrivateText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }
    else
    {
        ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_VALUE, &binVal );
        if( ret == CKR_OK )
        {
            mDSA_PublicText->setPlainText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            if( bVal == false )
                mDSA_PublicText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }

    JS_BIN_reset( &binVal );
}

void PriKeyInfoDlg::setEdDSAKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey,  bool bPri )
{
    int ret = 0;
    BIN binVal = {0,0};
    QString strParam;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    bool bVal = manApplet->settingsMgr()->displayValid();

    ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_EC_PARAMS, &binVal );
    if( ret == CKR_OK )
    {
        JS_BIN_reset( &binVal );
    }

    if( bPri == false )
    {
        ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_EC_POINT, &binVal );
        if( ret == CKR_OK )
        {
            if( binVal.pVal[1] == 32 )
                strParam = JS_EDDSA_PARAM_NAME_25519;
            else
                strParam = JS_EDDSA_PARAM_NAME_448;

            mEdDSA_RawPublicText->setPlainText( getHexString( &binVal.pVal[2], binVal.nLen - 2 ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            if( bVal == false )
                mEdDSA_RawPublicText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }
    else
    {
        ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_VALUE, &binVal );
        if( ret == CKR_OK )
        {
            if( binVal.nLen == 32 )
                strParam = JS_EDDSA_PARAM_NAME_25519;
            else
                strParam = JS_EDDSA_PARAM_NAME_448;

            mEdDSA_RawPrivateText->setPlainText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            if( bVal == false )
                mEdDSA_RawPrivateText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }

    mEdDSA_NameText->setText( JS_PKI_KEY_NAME_EDDSA );
    mEdDSA_ParamText->setText( strParam );
    JS_BIN_reset( &binVal );
}

void PriKeyInfoDlg::changeRSA_N()
{
    QString strN = mRSA_NText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strN );
    mRSA_NLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_E( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_ELenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_D()
{
    QString strD = mRSA_DText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strD );
    mRSA_DLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_P( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_PLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_Q( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_QLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_DMP1( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_DMP1LenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_DMQ1( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_DMQ1LenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_IQMP( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_IQMPLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeECC_PubX()
{
    QString strPubX = mECC_PubXText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPubX );
    mECC_PubXLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeECC_PubY()
{
    QString strPubY = mECC_PubYText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPubY );
    mECC_PubYLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeECC_Private()
{
    QString strPrivate = mECC_PrivateText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPrivate );
    mECC_PrivateLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_G()
{
    QString strG = mDSA_GText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strG );
    mDSA_GLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_P()
{
    QString strP = mDSA_PText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strP );
    mDSA_PLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_Q( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mDSA_QLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_Public()
{
    QString strPublic = mDSA_PublicText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPublic );
    mDSA_PublicLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_Private( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mDSA_PrivateLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeEdDSA_RawPublic()
{
    QString strRawPublic = mEdDSA_RawPublicText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strRawPublic );
    mEdDSA_RawPublicLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeEdDSA_RawPrivate()
{
    QString strRawPrivte = mEdDSA_RawPrivateText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strRawPrivte );
    mEdDSA_RawPrivateLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::clearAll()
{
    mRSA_DText->clear();
    mRSA_EText->clear();
    mRSA_NText->clear();
    mRSA_PText->clear();
    mRSA_QText->clear();
    mRSA_DMP1Text->clear();
    mRSA_DMQ1Text->clear();
    mRSA_IQMPText->clear();

    mECC_PubXText->clear();
    mECC_PubYText->clear();
    mECC_CurveOIDText->clear();
    mECC_PrivateText->clear();

    mDSA_GText->clear();
    mDSA_PText->clear();
    mDSA_QText->clear();
    mDSA_PublicText->clear();
    mDSA_PrivateText->clear();

    mEdDSA_NameText->clear();
    mEdDSA_RawPublicText->clear();
    mEdDSA_RawPrivateText->clear();
}


void PriKeyInfoDlg::clickCheckPubKey()
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();

    int ret = 0;
    if( pub_key_.nLen > 0 )
    {
        ret = JS_PKI_checkPublicKey( &pub_key_ );
    }
    else
    {
        BIN binPub = {0,0};
        if( pri_key_.nLen > 0 )
        {
            JS_PKI_getPubKeyFromPriKey( &pri_key_, &binPub );
        }
        else
        {
            if( session_ > 0 )
            {
                if( pub_handle_ > 0 )
                {
                    getPublicKey( pAPI, session_, pub_handle_, &binPub );
                }
                else if( pri_handle_ > 0 )
                {
                    getPublicKey( pAPI, session_, pri_handle_, &binPub );
                }
            }
        }

        ret = JS_PKI_checkPublicKey( &binPub );
        JS_BIN_reset( &binPub );
    }

    if( ret == JSR_VALID )
        manApplet->messageBox( tr( "PublicKey is valid" ), this );
    else
        manApplet->warningBox( tr( "PublicKey is invalid" ), this );
}




void PriKeyInfoDlg::setModeUI( bool bVal )
{
    QString strStyle;

    if( bVal == true )
        strStyle = "background-color:#FFFFFF";
    else
        strStyle = "background-color:#ddddff";

    if( key_type_ == JS_PKI_KEY_TYPE_RSA )
    {
        mRSA_EText->setStyleSheet( strStyle );
        mRSA_EText->setReadOnly(!bVal);
        mRSA_NText->setStyleSheet( strStyle );
        mRSA_NText->setReadOnly(!bVal);

        if( pri_key_.nLen > 0 )
        {
            mRSA_DText->setStyleSheet( strStyle );
            mRSA_DText->setReadOnly(!bVal);
            mRSA_PText->setStyleSheet( strStyle );
            mRSA_PText->setReadOnly(!bVal);
            mRSA_QText->setStyleSheet( strStyle );
            mRSA_QText->setReadOnly(!bVal);
            mRSA_DMP1Text->setStyleSheet( strStyle );
            mRSA_DMP1Text->setReadOnly(!bVal);
            mRSA_DMQ1Text->setStyleSheet( strStyle );
            mRSA_DMQ1Text->setReadOnly(!bVal);
            mRSA_IQMPText->setStyleSheet( strStyle );
            mRSA_IQMPText->setReadOnly(!bVal);
        }
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ECDSA || key_type_ == JS_PKI_KEY_TYPE_SM2 )
    {
        mECC_PubXText->setStyleSheet( strStyle );
        mECC_PubXText->setReadOnly( !bVal );
        mECC_PubYText->setStyleSheet( strStyle );
        mECC_PubYText->setReadOnly( !bVal );

        if( pri_key_.nLen > 0 )
        {
            mECC_PrivateText->setStyleSheet( strStyle );
            mECC_PrivateText->setReadOnly( !bVal );
        }
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_DSA )
    {
        mDSA_GText->setStyleSheet( strStyle );
        mDSA_GText->setReadOnly( !bVal );
        mDSA_PText->setStyleSheet( strStyle );
        mDSA_PText->setReadOnly( !bVal );
        mDSA_QText->setStyleSheet( strStyle );
        mDSA_QText->setReadOnly( !bVal );
        mDSA_PublicText->setStyleSheet( strStyle );
        mDSA_PublicText->setReadOnly( !bVal );

        if( pri_key_.nLen > 0 )
        {
            mDSA_PrivateText->setStyleSheet( strStyle );
            mDSA_PrivateText->setReadOnly( !bVal );
        }
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_EDDSA )
    {
        mEdDSA_RawPublicText->setStyleSheet( strStyle );
        mEdDSA_RawPublicText->setReadOnly( !bVal );

        if( pri_key_.nLen > 0 )
        {
            mEdDSA_RawPrivateText->setStyleSheet( strStyle );
            mEdDSA_RawPrivateText->setReadOnly( !bVal );
        }
    }
}


void PriKeyInfoDlg::setPrivateKey( const BIN *pPriKey )
{
    clearAll();
    BIN binPub = {0,0};
    BIN binKID = {0,0};

    QString strTitle = tr( "View Private Key" );

    mTitleLabel->setText( strTitle );
    setWindowTitle( strTitle );

    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );
    JS_BIN_copy( &pri_key_, pPriKey );
    session_ = 0;
    pub_handle_ = 0;
    pri_handle_ = 0;


    if( pPriKey == NULL || pPriKey->nLen <= 0 )
        return;

    key_type_ = JS_PKI_getPriKeyType( pPriKey );
    if( key_type_ < 0 ) return;

    JS_PKI_getPubKeyFromPriKey( pPriKey, &binPub );
    JS_PKI_getKeyIdentifier( &binPub, &binKID );

//    mKIDText->setText( getHexString(&binKID));
    setFixedLineText( mKIDText, getHexString( &binKID ));

    if( key_type_ == JS_PKI_KEY_TYPE_RSA )
    {
        mKeyTab->setCurrentIndex(0);
        mKeyTab->setTabEnabled(0, true);
        setRSAKey( pPriKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ECDSA || key_type_ == JS_PKI_KEY_TYPE_SM2 )
    {
        mKeyTab->setCurrentIndex(1);
        mKeyTab->setTabEnabled(1, true);
        setECCKey( pPriKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_DSA )
    {
        mKeyTab->setCurrentIndex( 2 );
        mKeyTab->setTabEnabled(2, true);
        setDSAKey( pPriKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_EDDSA )
    {
        mKeyTab->setCurrentIndex( 3 );
        mKeyTab->setTabEnabled(3, true);
        setEdDSAKey( key_type_, pPriKey );
    }
    else
    {
        manApplet->warningBox( tr("Private key algorithm(%1) not supported").arg( key_type_ ), this);
    }

    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binKID );
}

void PriKeyInfoDlg::setPublicKey( const BIN *pPubKey )
{
    clearAll();
    BIN binKID = {0,0};

    QString strTitle = tr( "View Public Key" );

    mTitleLabel->setText( strTitle );
    setWindowTitle( strTitle );

    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );
    JS_BIN_copy( &pub_key_, pPubKey );

    session_ = 0;
    pub_handle_ = 0;
    pri_handle_ = 0;

    if( pPubKey == NULL || pPubKey->nLen <= 0 )
        return;

    key_type_ = JS_PKI_getPubKeyType( pPubKey );

    JS_PKI_getKeyIdentifier( pPubKey, &binKID );
//    mKIDText->setText( getHexString( &binKID) );
    setFixedLineText( mKIDText, getHexString( &binKID ));

    if( key_type_ == JS_PKI_KEY_TYPE_RSA )
    {
        mKeyTab->setCurrentIndex(0);
        mKeyTab->setTabEnabled(0, true);
        setRSAKey( pPubKey, false );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ECDSA || key_type_ == JS_PKI_KEY_TYPE_SM2 )
    {
        mKeyTab->setCurrentIndex(1);
        mKeyTab->setTabEnabled(1, true);
        setECCKey( pPubKey, false );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_DSA )
    {
        mKeyTab->setCurrentIndex( 2 );
        mKeyTab->setTabEnabled(2, true);
        setDSAKey( pPubKey, false );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_EDDSA  )
    {
        mKeyTab->setCurrentIndex( 3 );
        mKeyTab->setTabEnabled(3, true);
        setEdDSAKey( key_type_, pPubKey, false );
    }
    else
    {
        manApplet->warningBox( tr("Public key algorithm(%1) not supported").arg( key_type_ ), this);
    }

    JS_BIN_reset( &binKID );
}

void PriKeyInfoDlg::setPrivateKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey )
{
    clearAll();
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();

    int ret = 0;
    BIN binVal = {0,0};
    long uKeyType = 0;
    BIN binPub = {0,0};
    BIN binKID = {0,0};

    QString strTitle = tr( "View Private Key" );

    mTitleLabel->setText( strTitle );
    setWindowTitle( strTitle );

    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );

    if( hKey < 0 || hSession < 0) return;
    session_ = hSession;
    pri_handle_ = hKey;
    pub_handle_ = 0;

    ret = getPublicKey( manApplet->cryptokiAPI(), hSession, hKey, &binPub );
    if( ret == 0 )
    {
        JS_PKI_getKeyIdentifier( &binPub, &binKID );
//        mKIDText->setText( getHexString( &binKID ));
        setFixedLineText( mKIDText, getHexString( &binKID ));
    }

    ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_KEY_TYPE, &binVal );
    if( ret != 0 ) goto end;

    mCheckPubKeyBtn->setEnabled( false );

    memcpy( &uKeyType, binVal.pVal, binVal.nLen );

    if( uKeyType == CKK_RSA )
    {
        mKeyTab->setCurrentIndex(0);
        mKeyTab->setTabEnabled(0, true);
        setRSAKey( hSession, hKey, true );
    }
    else if( uKeyType == CKK_EC )
    {
        mKeyTab->setCurrentIndex(1);
        mKeyTab->setTabEnabled(1, true);
        setECCKey( hSession, hKey, true );
    }
    else if( uKeyType == CKK_DSA )
    {
        mKeyTab->setCurrentIndex( 2 );
        mKeyTab->setTabEnabled(2, true);
        setDSAKey( hSession, hKey, true );
    }
    else if( uKeyType == CKK_EC_EDWARDS )
    {
        mKeyTab->setCurrentIndex( 3 );
        mKeyTab->setTabEnabled(3, true);
        setEdDSAKey( hSession, hKey, true );
    }
    else
    {
        manApplet->warningBox( tr("Private key algorithm(%1) not supported").arg( uKeyType ), this);
    }

end :
    JS_BIN_reset( &binVal );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binKID );
}

void PriKeyInfoDlg::setPublicKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey )
{
    clearAll();
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();

    int ret = 0;
    BIN binVal = {0,0};
    long uKeyType = 0;
    BIN binPub = {0,0};
    BIN binKID = {0,0};

    QString strTitle = tr( "View Public Key" );

    mTitleLabel->setText( strTitle );
    setWindowTitle( strTitle );

    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );

    if( hKey < 0 || hSession < 0) return;
    session_ = hSession;
    pub_handle_ = hKey;
    pri_handle_ = -1;

    ret = getPublicKey( manApplet->cryptokiAPI(), hSession, hKey, &binPub );
    if( ret == 0 )
    {
        JS_PKI_getKeyIdentifier( &binPub, &binKID );
//        mKIDText->setText( getHexString( &binKID ));
        setFixedLineText( mKIDText, getHexString( &binKID ));
    }

    ret = pAPI->GetAttributeValue2( hSession, hKey, CKA_KEY_TYPE, &binVal );
    if( ret != 0 ) goto end;

    memcpy( &uKeyType, binVal.pVal, binVal.nLen );

    if( uKeyType == CKK_RSA )
    {
        mKeyTab->setCurrentIndex(0);
        mKeyTab->setTabEnabled(0, true);
        setRSAKey( hSession, hKey, false );
    }
    else if( uKeyType == CKK_EC )
    {
        mKeyTab->setCurrentIndex(1);
        mKeyTab->setTabEnabled(1, true);
        setECCKey( hSession, hKey, false );
    }
    else if( uKeyType == CKK_DSA )
    {
        mKeyTab->setCurrentIndex( 2 );
        mKeyTab->setTabEnabled(2, true);
        setDSAKey( hSession, hKey, false );
    }
    else if( uKeyType == CKK_EC_EDWARDS )
    {
        mKeyTab->setCurrentIndex( 3 );
        mKeyTab->setTabEnabled(3, true);
        setEdDSAKey( hSession, hKey, false );
    }
    else
    {
        manApplet->warningBox( tr("Public key algorithm(%1) not supported").arg( uKeyType ), this);
    }

end :
    JS_BIN_reset( &binVal );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binKID );
}

void PriKeyInfoDlg::readPrivateKey( BIN *pPriKey )
{
    if( pPriKey == NULL ) return;

    JS_BIN_copy( pPriKey, &pri_key_ );
}

void PriKeyInfoDlg::readPublicKey( BIN *pPubKey )
{
    if( pPubKey == NULL ) return;

    JS_BIN_copy( pPubKey, &pub_key_ );
}
