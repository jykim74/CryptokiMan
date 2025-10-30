/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "create_ec_pub_key_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "common.h"
#include "cryptoki_api.h"
#include "js_pki.h"
#include "js_pki_raw.h"
#include "js_pki_key.h"
#include "js_pki_tools.h"

static QStringList sFalseTrue = { "false", "true" };

CreateECPubKeyDlg::CreateECPubKeyDlg(bool bED, QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    is_ed_ = bED;

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mECPointsText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECPoints(const QString&)));
    connect( mECParamsText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECParams(const QString&)));

    initialize();
    setDefaults();

    tabWidget->setCurrentIndex(0);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mFirstTab->layout()->setSpacing(5);
    mFirstTab->layout()->setMargin(5);
    mSecondTab->layout()->setSpacing(5);
    mSecondTab->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CreateECPubKeyDlg::~CreateECPubKeyDlg()
{

}

void CreateECPubKeyDlg::setSlotIndex(int index)
{
    slot_index_ = index;
    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    if( index >= 0 )
    {
        slot_info_ = slot_infos.at(slot_index_);
        mSlotNameText->setText( slot_info_.getDesc() );
    }

    mSlotIDText->setText( QString( "%1").arg(slot_info_.getSlotID()));
    mSessionText->setText( QString("%1").arg(slot_info_.getSessionHandle()));
    mLoginText->setText( slot_info_.getLogin() ? "YES" : "NO" );
}


void CreateECPubKeyDlg::initialize()
{
    QString strTitle;

    if( is_ed_ )
        strTitle = tr( "Create EDDSA public key" );
    else
        strTitle = tr( "Create ECDSA public key" );

    setWindowTitle( strTitle );

    mLabelText->setPlaceholderText( tr("String value" ));
    mSubjectText->setPlaceholderText( tr("DN value"));

    setLineEditHexOnly(mIDText, tr("Hex value"));
    setLineEditHexOnly( mECParamsText, tr("Hex value" ));
    setLineEditHexOnly( mECPointsText, tr("Hex value" ));
}

void CreateECPubKeyDlg::initAttributes()
{
    if( is_ed_ == true )
        mParamCombo->addItems( kEdDSAOptionList );
    else
        mParamCombo->addItems( kECDSAOptionList );

    mSubjectTypeCombo->addItems(kDNTypeList);

    mPrivateCombo->addItems(sFalseTrue);
    mPrivateCombo->setCurrentIndex(1);

    mEncryptCombo->addItems(sFalseTrue);
    mEncryptCombo->setCurrentIndex(1);

    mWrapCombo->addItems(sFalseTrue);
    mWrapCombo->setCurrentIndex(1);

    mVerifyCombo->addItems(sFalseTrue);
    mVerifyCombo->setCurrentIndex(1);

    mVerifyRecoverCombo->addItems(sFalseTrue);
    mVerifyRecoverCombo->setCurrentIndex(1);

    mDeriveCombo->addItems(sFalseTrue);
    mDeriveCombo->setCurrentIndex(1);

    mModifiableCombo->addItems(sFalseTrue);
    mModifiableCombo->setCurrentIndex(1);

    mCopyableCombo->addItems(sFalseTrue);
    mCopyableCombo->setCurrentIndex(1);

    mDestroyableCombo->addItems(sFalseTrue);
    mDestroyableCombo->setCurrentIndex(1);

    mTokenCombo->addItems(sFalseTrue);
    mTokenCombo->setCurrentIndex(1);

    mTrustedCombo->addItems(sFalseTrue);
    mTrustedCombo->setCurrentIndex(1);

    QDate nowDate = QDate::currentDate();
    mStartDateEdit->setDate(nowDate);
    mEndDateEdit->setDate(nowDate);
}

void CreateECPubKeyDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
    mVerifyRecoverCombo->setEnabled(mVerifyRecoverCheck->isChecked());
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void CreateECPubKeyDlg::connectAttributes()
{
    connect( mGenKeyBtn, SIGNAL(clicked()), this, SLOT(clickGenKey()));
    connect( mFindKeyBtn, SIGNAL(clicked()), this, SLOT(clickFindKey()));
    connect( mUseSKICheck, SIGNAL(clicked()), this, SLOT(clickUseSKI()));

    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mEncryptCheck, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mWrapCheck, SIGNAL(clicked()), this, SLOT(clickWrap()));
    connect( mVerifyCheck, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mVerifyRecoverCheck, SIGNAL(clicked()), this, SLOT(clickVerifyRecover()));
    connect( mDeriveCheck, SIGNAL(clicked()), this, SLOT(clickDerive()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mCopyableCheck, SIGNAL(clicked()), this, SLOT(clickCopyable()));
    connect( mDestroyableCheck, SIGNAL(clicked()), this, SLOT(clickDestroyable()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mTrustedCheck, SIGNAL(clicked()), this, SLOT(clickTrusted()));
    connect( mStartDateCheck, SIGNAL(clicked()), this, SLOT(clickStartDate()));
    connect( mEndDateCheck, SIGNAL(clicked()), this, SLOT(clickEndDate()));
}

void CreateECPubKeyDlg::accept()
{
    int rv = -1;

    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL    bTrue = CK_TRUE;
    CK_BBOOL    bFalse = CK_FALSE;
    CK_OBJECT_HANDLE    hObject = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = -1;

    if( is_ed_ == true )
        keyType = CKK_EC_EDWARDS;
    else
        keyType = CKK_ECDSA;

    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strECParams = mECParamsText->text();
    BIN binECParams = {0,0};

    if( !strECParams.isEmpty() )
    {
        JS_BIN_decodeHex( strECParams.toStdString().c_str(), &binECParams );
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = binECParams.pVal;
        sTemplate[uCount].ulValueLen = binECParams.nLen;
        uCount++;
    }

    QString strECPoints = mECPointsText->text();
    BIN binECPoints = {0,0};

    if( !strECPoints.isEmpty() )
    {
        JS_BIN_decodeHex( strECPoints.toStdString().c_str(), &binECPoints );
        sTemplate[uCount].type = CKA_EC_POINT;
        sTemplate[uCount].pValue = binECPoints.pVal;
        sTemplate[uCount].ulValueLen = binECPoints.nLen;
        uCount++;
    }

    QString strLabel = mLabelText->text();
    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strSubject = mSubjectText->text();
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        if( mSubjectTypeCombo->currentText() == "Text" )
            JS_PKI_getDERFromDN( strSubject.toStdString().c_str(), &binSubject );
        else
            JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );

        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
        uCount++;
    }


    QString strID = mIDText->text();
    BIN binID = {0,0};

    if( mUseSKICheck->isChecked() )
    {
        getSKI( &binID );
    }
    else
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    }

    if( binID.nLen > 0 )
    {
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    if( mDeriveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DERIVE;
        sTemplate[uCount].pValue = ( mDeriveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mEncryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_ENCRYPT;
        sTemplate[uCount].pValue = ( mEncryptCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mModifiableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = ( mModifiableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        sTemplate[uCount].pValue = ( mCopyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = ( mPrivateCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = ( mTokenCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mTrustedCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TRUSTED;
        sTemplate[uCount].pValue = ( mTrustedCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mVerifyCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_VERIFY;
        sTemplate[uCount].pValue = ( mVerifyCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mVerifyRecoverCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_VERIFY_RECOVER;
        sTemplate[uCount].pValue = ( mVerifyRecoverCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mWrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_WRAP;
        sTemplate[uCount].pValue = ( mWrapCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mStartDateCheck->isChecked() )
    {
        getQDateToCKDate( mStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mEndDateCheck->isChecked() )
    {
        getQDateToCKDate( mEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binECParams );
    JS_BIN_reset( &binECPoints );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "EC public key creation failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("EC public key creation successful [Handle: %1]").arg( hObject ), this );
    manApplet->showTypeList( slot_index_, HM_ITEM_TYPE_PUBLICKEY );

    QDialog::accept();
}

void CreateECPubKeyDlg::clickGenKey()
{
    int ret = 0;
    BIN binPub = {0,0};
    BIN binPri = {0,0};
    BIN binOID = {0,0};
    JECKeyVal sECKey;
    JRawKeyVal sRawKey;

    QString strParam = mParamCombo->currentText();

    memset( &sECKey, 0x00, sizeof(sECKey));
    memset( &sRawKey, 0x00, sizeof(sRawKey));

    if( is_ed_ == true )
    {
        int nKeyType = -1;
        QString strECParam;
        QString strECPoint;

        if( strParam == "ED25519" )
        {
            nKeyType = JS_EDDSA_PARAM_25519;
            strECParam = getHexString( kCurveNameX25519, sizeof(kCurveNameX25519));
        }
        else
        {
            nKeyType = JS_EDDSA_PARAM_448;
            strECParam = getHexString( kCurveNameX448, sizeof(kCurveNameX448));
        }

        ret = JS_PKI_EdDSA_GenKeyPair( nKeyType, &binPub, &binPri );
        if( ret != 0 ) goto end;

        strECPoint = "04";
        strECPoint += QString( "%1" ).arg( binPub.nLen, 2, 16, QLatin1Char('0'));
        strECPoint += getHexString( &binPub );

        mECPointsText->setText( strECPoint );
        mECParamsText->setText( strECParam );
    }
    else
    {
        QString strPoints = "04";

        JS_PKI_getOIDFromString( strParam.toStdString().c_str(), &binOID );

        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getECKeyVal( &binPri, &sECKey );
        if( ret != 0 ) goto end;

        strPoints += sECKey.pPubX;
        strPoints += sECKey.pPubY;

        mECParamsText->setText( getHexString( binOID.pVal, binOID.nLen ));
        mECPointsText->setText( strPoints );
    }

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binOID );
    JS_PKI_resetECKeyVal( &sECKey );
    JS_PKI_resetRawKeyVal( &sRawKey );
}

void CreateECPubKeyDlg::clickUseSKI()
{
    bool bVal = mUseSKICheck->isChecked();
    mIDText->setEnabled( !bVal );
}

void CreateECPubKeyDlg::clickFindKey()
{
    int ret = 0;
    int nKeyType = -1;
    int nParam = -1;
    BIN binKey = {0,0};
    BIN binOID = {0,0};
    JECKeyVal sECKey;
    JRawKeyVal sRawKey;

    QString strPath;
    QString fileName = manApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.length() < 1 ) return;

    QString strPoints = "04";

    memset( &sECKey, 0x00, sizeof(sECKey));
    memset( &sRawKey, 0x00, sizeof(sRawKey));

    ret = JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binKey );
    if( ret < 0 )
    {
        manApplet->elog( QString( "failed to read key [%1]").arg( ret) );
        goto end;
    }

    JS_PKI_getPriKeyAlgParam( &binKey, &nKeyType, &nParam );

    if( is_ed_ == true )
    {
        if( nKeyType < 0 )
        {
            nKeyType = JS_PKI_getPubKeyType( &binKey );
            if( nKeyType != JS_PKI_KEY_TYPE_EDDSA )
            {
                manApplet->elog( QString( "invalid public key type (%1)").arg( nKeyType ));
                goto end;
            }

            ret = JS_PKI_getECKeyValFromPub( &binKey, &sECKey );
            if( ret != 0 ) goto end;
        }
        else if( nKeyType != JS_PKI_KEY_TYPE_EDDSA )
        {
            manApplet->elog( QString( "invalid private key type (%1)").arg( nKeyType ));
            goto end;
        }
        else
        {
            ret = JS_PKI_getRawKeyVal( &binKey, &sRawKey );
            if( ret != 0 ) goto end;
        }

        QString strECParam;
        QString strECPoint;

        if( nParam == JS_EDDSA_PARAM_25519 )
        {

            strECParam = getHexString( kCurveNameX25519, sizeof(kCurveNameX25519));
        }
        else
        {
            strECParam = getHexString( kCurveNameX448, sizeof(kCurveNameX448));
        }

        strECPoint = "04";
        strECPoint += QString( "%1" ).arg( strlen(sRawKey.pPub)/2, 2, 16, QLatin1Char('0'));
        strECPoint += sRawKey.pPub;

        mECPointsText->setText( strECPoint );
        mECParamsText->setText( strECParam );
    }
    else
    {
        if( nKeyType < 0 )
        {
            nKeyType = JS_PKI_getPubKeyType( &binKey );
            if( nKeyType != JS_PKI_KEY_TYPE_ECDSA )
            {
                manApplet->elog( QString( "invalid public key type (%1)").arg( nKeyType ));
                goto end;
            }

            ret = JS_PKI_getECKeyValFromPub( &binKey, &sECKey );
            if( ret != 0 ) goto end;
        }
        else if( nKeyType != JS_PKI_KEY_TYPE_ECDSA )
        {
            manApplet->elog( QString( "invalid private key type (%1)").arg( nKeyType ));
            goto end;
        }
        else
        {
            ret = JS_PKI_getECKeyVal( &binKey, &sECKey );
            if( ret != 0 ) goto end;
        }

        JS_PKI_getOIDFromString( sECKey.pCurveOID, &binOID );

        strPoints += sECKey.pPubX;
        strPoints += sECKey.pPubY;

        mECParamsText->setText( getHexString( binOID.pVal, binOID.nLen ));
        mECPointsText->setText( strPoints );
    }

    ret = 0;

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binOID );
    JS_PKI_resetECKeyVal( &sECKey );
    JS_PKI_resetRawKeyVal( &sRawKey );

    if( ret != 0 ) manApplet->warningBox( tr( "failed to get key value [%1]").arg(ret), this );
}

void CreateECPubKeyDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void CreateECPubKeyDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void CreateECPubKeyDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void CreateECPubKeyDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}

void CreateECPubKeyDlg::clickVerifyRecover()
{
    mVerifyRecoverCombo->setEnabled(mVerifyRecoverCheck->isChecked());
}

void CreateECPubKeyDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void CreateECPubKeyDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void CreateECPubKeyDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void CreateECPubKeyDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}

void CreateECPubKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void CreateECPubKeyDlg::clickTrusted()
{
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
}

void CreateECPubKeyDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void CreateECPubKeyDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void CreateECPubKeyDlg::changeECPoints( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mECPointsLenText->setText( QString("%1").arg(strLen));
}

void CreateECPubKeyDlg::changeECParams( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mECParamsLenText->setText( QString("%1").arg(strLen));
}

void CreateECPubKeyDlg::setDefaults()
{
    mParamCombo->setCurrentText( "prime256v1" );

//    mLabelText->setText( "EC Public Key Label" );
//    mIDText->setText( "01020304" );

    mUseSKICheck->setChecked(true);
    clickUseSKI();

    QDateTime nowTime;
    nowTime.setSecsSinceEpoch( time(NULL) );

    mStartDateEdit->setDate( nowTime.date() );
    mEndDateEdit->setDate( nowTime.date() );
}

int CreateECPubKeyDlg::getSKI( BIN *pSKI )
{
    int ret = 0;
    JECKeyVal sECKey;

    BIN binPub = {0,0};
    BIN binOID = {0,0};
    BIN binPoints = {0,0};
    BIN binPubX = {0,0};
    BIN binPubY = {0,0};
    char *pHexPubX = NULL;
    char *pHexPubY = NULL;

    char sOID[128];
    QString strParam = mECParamsText->text();
    QString strPoints = mECPointsText->text();

    memset( &sECKey, 0x00, sizeof(sECKey));
    memset(sOID, 0x00, sizeof(sOID));

    JS_BIN_decodeHex( strPoints.toStdString().c_str(), &binPoints );
    JS_BIN_decodeHex( strParam.toStdString().c_str(), &binOID );

    ret = JS_PKI_getStringFromOID( &binOID, sOID );
    if( ret != 0 )
    {
        manApplet->elog( QString( "invalid parameters [%1]").arg(ret));
        goto end;
    }

    if( binPoints.nLen <= 3 )
    {
        manApplet->elog( QString( "Invalid Points value" ) );
        goto end;
    }

    JS_BIN_set( &binPubX, &binPoints.pVal[1], (binPoints.nLen-1) / 2 );
    JS_BIN_set( &binPubY, &binPoints.pVal[1 + binPubX.nLen], binPubX.nLen );
    JS_BIN_encodeHex( &binPubX, &pHexPubX );
    JS_BIN_encodeHex( &binPubY, &pHexPubY );

    JS_PKI_setECKeyVal( &sECKey,
                        sOID,
                        pHexPubX,
                        pHexPubY,
                        NULL );

    ret = JS_PKI_encodeECPublicKey( &sECKey, &binPub );
    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to encode private key [%1]").arg(ret));
        goto end;
    }

    ret = JS_PKI_getKeyIdentifier( &binPub, pSKI );
    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to get key identifier [%1]").arg(ret));
        goto end;
    }

end :
    JS_PKI_resetECKeyVal( &sECKey );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binOID );
    JS_BIN_reset( &binPoints );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );
    if( pHexPubX ) JS_free( pHexPubX );
    if( pHexPubY ) JS_free( pHexPubY );

    return ret;
}
