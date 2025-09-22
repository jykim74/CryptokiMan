/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "create_rsa_pri_key_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "common.h"
#include "cryptoki_api.h"
#include "js_pki.h"
#include "js_pki_eddsa.h"
#include "js_pki_key.h"
#include "js_pki_tools.h"

static QStringList sFalseTrue = { "false", "true" };

CreateRSAPriKeyDlg::CreateRSAPriKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mModulesText, SIGNAL(textChanged(const QString&)), this, SLOT(changeModules(const QString&)));
    connect( mPubExponentText, SIGNAL(textChanged(const QString&)), this, SLOT(changePubExponent(const QString&)));
    connect( mPriExponentText, SIGNAL(textChanged(const QString&)), this, SLOT(changePriExponent(const QString&)));
    connect( mPrime1Text, SIGNAL(textChanged(const QString&)), this, SLOT(changePrime1(const QString&)));
    connect( mPrime2Text, SIGNAL(textChanged(const QString&)), this, SLOT(changePrime2(const QString&)));
    connect( mExponent1Text, SIGNAL(textChanged(const QString&)), this, SLOT(changeExponent1(const QString&)));
    connect( mExponent2Text, SIGNAL(textChanged(const QString&)), this, SLOT(changeExponent2(const QString&)));
    connect( mCoefficientText, SIGNAL(textChanged(const QString&)), this, SLOT(changeCoefficient(const QString&)));

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

CreateRSAPriKeyDlg::~CreateRSAPriKeyDlg()
{

}

void CreateRSAPriKeyDlg::setSlotIndex(int index)
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


void CreateRSAPriKeyDlg::initialize()
{
    mLabelText->setPlaceholderText( tr("String value" ));
    mIDText->setPlaceholderText( tr("Hex value" ));
    mPubKeyInfoText->setPlaceholderText( tr("Hex value" ));

    mModulesText->setPlaceholderText( tr("Hex value" ));
    mPubExponentText->setPlaceholderText( tr("Hex value" ));
    mPriExponentText->setPlaceholderText( tr("Hex value" ));
    mPrime1Text->setPlaceholderText( tr("Hex value" ));
    mPrime2Text->setPlaceholderText( tr("Hex value" ));
    mExponent1Text->setPlaceholderText( tr("Hex value" ));
    mExponent2Text->setPlaceholderText( tr("Hex value" ));
    mCoefficientText->setPlaceholderText( tr("Hex value" ));
}

void CreateRSAPriKeyDlg::initAttributes()
{
    mParamCombo->addItems( kRSAOptionList );
    mSubjectTypeCombo->addItems(kDNTypeList);

    mPrivateCombo->addItems(sFalseTrue);
    mPrivateCombo->setCurrentIndex(1);

    mDecryptCombo->addItems(sFalseTrue);
    mDecryptCombo->setCurrentIndex(1);

    mSignCombo->addItems(sFalseTrue);
    mSignCombo->setCurrentIndex(1);

    mSignRecoverCombo->addItems(sFalseTrue);
    mSignRecoverCombo->setCurrentIndex(1);

    mUnwrapCombo->addItems(sFalseTrue);
    mUnwrapCombo->setCurrentIndex(1);

    mSensitiveCombo->addItems(sFalseTrue);
    mSensitiveCombo->setCurrentIndex(1);

    mDeriveCombo->addItems(sFalseTrue);
    mDeriveCombo->setCurrentIndex(1);

    mModifiableCombo->addItems(sFalseTrue);
    mModifiableCombo->setCurrentIndex(1);

    mCopyableCombo->addItems(sFalseTrue);
    mCopyableCombo->setCurrentIndex(1);

    mDestroyableCombo->addItems(sFalseTrue);
    mDestroyableCombo->setCurrentIndex(1);

    mExtractableCombo->addItems(sFalseTrue);
    mExtractableCombo->setCurrentIndex(1);

    mTokenCombo->addItems(sFalseTrue);
    mTokenCombo->setCurrentIndex(1);

    QDate nowDate = QDate::currentDate();
    mStartDateEdit->setDate(nowDate);
    mEndDateEdit->setDate(nowDate);
}

void CreateRSAPriKeyDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
    mSignCombo->setEnabled(mSignCheck->isChecked());
    mSignRecoverCombo->setEnabled(mSignRecoverCheck->isChecked());
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void CreateRSAPriKeyDlg::connectAttributes()
{
    connect( mFindKeyBtn, SIGNAL(clicked()), this, SLOT(clickFindKey()));
    connect( mGenKeyBtn, SIGNAL(clicked()), this, SLOT(clickGenKey()));
    connect( mUseSKICheck, SIGNAL(clicked()), this, SLOT(clickUseSKI()));
    connect( mUseSPKICheck, SIGNAL(clicked()), this, SLOT(clickUseSPKI()));

    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mDecryptCheck, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mUnwrapCheck, SIGNAL(clicked()), this, SLOT(clickUnwrap()));
    connect( mSignCheck, SIGNAL(clicked()), this, SLOT(clickSign()));
    connect( mSignRecoverCheck, SIGNAL(clicked()), this, SLOT(clickSignRecover()));
    connect( mDeriveCheck, SIGNAL(clicked()), this, SLOT(clickDerive()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mCopyableCheck, SIGNAL(clicked()), this, SLOT(clickCopyable()));
    connect( mDestroyableCheck, SIGNAL(clicked()), this, SLOT(clickDestroyable()));
    connect( mSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickSensitive()));
    connect( mExtractableCheck, SIGNAL(clicked()), this, SLOT(clickExtractable()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mStartDateCheck, SIGNAL(clicked()), this, SLOT(clickStartDate()));
    connect( mEndDateCheck, SIGNAL(clicked()), this, SLOT(clickEndDate()));
}

void CreateRSAPriKeyDlg::accept()
{
    int rv = -1;

    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;

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

    QString strModules = mModulesText->text();
    BIN binModules = {0,0};

    if( !strModules.isEmpty() )
    {
        JS_BIN_decodeHex( strModules.toStdString().c_str(), &binModules );
        sTemplate[uCount].type = CKA_MODULUS;
        sTemplate[uCount].pValue = binModules.pVal;
        sTemplate[uCount].ulValueLen = binModules.nLen;
        uCount++;
    }

    QString strPublicExponent = mPubExponentText->text();
    BIN binPublicExponent = {0,0};

    if( !strPublicExponent.isEmpty() )
    {
        JS_BIN_decodeHex( strPublicExponent.toStdString().c_str(), &binPublicExponent );
        sTemplate[uCount].type = CKA_PUBLIC_EXPONENT;
        sTemplate[uCount].pValue = binPublicExponent.pVal;
        sTemplate[uCount].ulValueLen = binPublicExponent.nLen;
        uCount++;
    }

    QString strPrivateExponent = mPriExponentText->text();
    BIN binPrivateExponent = {0,0};

    if( !strPrivateExponent.isEmpty() )
    {
        JS_BIN_decodeHex( strPrivateExponent.toStdString().c_str(), &binPrivateExponent );
        sTemplate[uCount].type = CKA_PRIVATE_EXPONENT;
        sTemplate[uCount].pValue = binPrivateExponent.pVal;
        sTemplate[uCount].ulValueLen = binPrivateExponent.nLen;
        uCount++;
    }

    QString strPrime1 = mPrime1Text->text();
    BIN binPrime1 = {0,0};

    if( !strPrime1.isEmpty() )
    {
        JS_BIN_decodeHex( strPrime1.toStdString().c_str(), &binPrime1 );
        sTemplate[uCount].type = CKA_PRIME_1;
        sTemplate[uCount].pValue = binPrime1.pVal;
        sTemplate[uCount].ulValueLen = binPrime1.nLen;
        uCount++;
    }

    QString strPrime2 = mPrime2Text->text();
    BIN binPrime2 = {0,0};

    if( !strPrime2.isEmpty() )
    {
        JS_BIN_decodeHex( strPrime2.toStdString().c_str(), &binPrime2 );
        sTemplate[uCount].type = CKA_PRIME_2;
        sTemplate[uCount].pValue = binPrime2.pVal;
        sTemplate[uCount].ulValueLen = binPrime2.nLen;
        uCount++;
    }

    QString strExponent1 = mExponent1Text->text();
    BIN binExponent1 = {0,0};

    if( !strExponent1.isEmpty() )
    {
        JS_BIN_decodeHex( strExponent1.toStdString().c_str(), &binExponent1 );
        sTemplate[uCount].type = CKA_EXPONENT_1;
        sTemplate[uCount].pValue = binExponent1.pVal;
        sTemplate[uCount].ulValueLen = binExponent1.nLen;
        uCount++;
    }

    QString strExponent2 = mExponent2Text->text();
    BIN binExponent2 = {0,0};

    if( !strExponent2.isEmpty() )
    {
        JS_BIN_decodeHex( strExponent2.toStdString().c_str(), &binExponent2 );
        sTemplate[uCount].type = CKA_EXPONENT_2;
        sTemplate[uCount].pValue = binExponent2.pVal;
        sTemplate[uCount].ulValueLen = binExponent2.nLen;
        uCount++;
    }

    QString strCoefficient = mCoefficientText->text();
    BIN binCoefficient = {0,0};

    if( !strCoefficient.isEmpty() )
    {
        JS_BIN_decodeHex( strCoefficient.toStdString().c_str(), &binCoefficient );
        sTemplate[uCount].type = CKA_COEFFICIENT;
        sTemplate[uCount].pValue = binCoefficient.pVal;
        sTemplate[uCount].ulValueLen = binCoefficient.nLen;
        uCount++;
    }

    QString strLabel = mLabelText->text();
    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length());
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mIDText->text();
    BIN binID = {0,0};
    BIN binPub = {0,0};

    if( mUseSKICheck->isChecked() )
    {
        getSKI_SPKI( &binID, &binPub );
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

    if( mUseSPKICheck->isChecked() == false )
    {
        JS_BIN_reset( &binPub );
        QString strPubKeyInfo = mPubKeyInfoText->text();

        if( strPubKeyInfo.length() > 0 ) JS_BIN_decodeHex( strPubKeyInfo.toStdString().c_str(), &binPub );
    }

    if( binPub.nLen > 0 )
    {
        sTemplate[uCount].type = CKA_PUBLIC_KEY_INFO;
        sTemplate[uCount].pValue = binPub.pVal;
        sTemplate[uCount].ulValueLen = binPub.nLen;
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

    if( mDecryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DECRYPT;
        sTemplate[uCount].pValue = ( mDecryptCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mDeriveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DERIVE;
        sTemplate[uCount].pValue = ( mDeriveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mExtractableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_EXTRACTABLE;
        sTemplate[uCount].pValue = ( mExtractableCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mSensitiveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SENSITIVE;
        sTemplate[uCount].pValue = ( mSensitiveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mSignCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN;
        sTemplate[uCount].pValue = ( mSignCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mSignRecoverCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN_RECOVER;
        sTemplate[uCount].pValue = ( mSignRecoverCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mUnwrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_UNWRAP;
        sTemplate[uCount].pValue = ( mUnwrapCombo->currentIndex() ? &bTrue : &bFalse );
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

    CK_OBJECT_HANDLE hObject = 0;

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binModules );
    JS_BIN_reset( &binPublicExponent );
    JS_BIN_reset( &binPrivateExponent );
    JS_BIN_reset( &binPrime1 );
    JS_BIN_reset( &binPrime2 );
    JS_BIN_reset( &binExponent1 );
    JS_BIN_reset( &binExponent2 );
    JS_BIN_reset( &binCoefficient );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binSubject );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("RSA private key creation failure [%1]").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("RSA private key creation successful [Handle: %1]").arg( hObject ), this );
    manApplet->showTypeList( slot_index_, HM_ITEM_TYPE_PRIVATEKEY );

    QDialog::accept();
}

void CreateRSAPriKeyDlg::clickGenKey()
{
    int ret = 0;
    BIN binPub = {0,0};
    BIN binPri = {0,0};
    JRSAKeyVal sRSAKey;

    int nKeyLen = mParamCombo->currentText().toInt();
    int nE = mEText->text().toInt();

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));

    ret = JS_PKI_RSAGenKeyPair( nKeyLen, nE, &binPub, &binPri );
    if( ret != 0 ) goto end;

    ret = JS_PKI_getRSAKeyVal( &binPri, &sRSAKey );
    if( ret != 0 ) goto end;

    mModulesText->setText( sRSAKey.pN );
    mPubExponentText->setText( sRSAKey.pE );
    mPriExponentText->setText( sRSAKey.pD );
    mPrime1Text->setText( sRSAKey.pP );
    mPrime2Text->setText( sRSAKey.pQ );
    mExponent1Text->setText( sRSAKey.pDMP1 );
    mExponent2Text->setText( sRSAKey.pDMQ1 );
    mCoefficientText->setText( sRSAKey.pIQMP );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_PKI_resetRSAKeyVal( &sRSAKey );
}

void CreateRSAPriKeyDlg::clickFindKey()
{
    int ret = 0;
    int nKeyType = -1;
    BIN binPri = {0,0};
    JRSAKeyVal  sRSAKey;
    QString strPath;
    QString fileName = manApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.length() < 1 ) return;

    memset( &sRSAKey, 0x00, sizeof(sRSAKey ));

    ret = JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binPri );
    if( ret < 0 )
    {
        manApplet->elog( QString( "failed to read private key [%1]").arg( ret) );
        goto end;
    }

    nKeyType = JS_PKI_getPriKeyType( &binPri );
    if( nKeyType != JS_PKI_KEY_TYPE_RSA )
    {
        manApplet->elog( QString( "invalid private key type (%1)").arg( nKeyType ));
        goto end;
    }

    ret = JS_PKI_getRSAKeyVal( &binPri, &sRSAKey );
    if( ret != 0 ) goto end;

    mModulesText->setText( sRSAKey.pN );
    mPubExponentText->setText( sRSAKey.pE );
    mPriExponentText->setText( sRSAKey.pD );
    mPrime1Text->setText( sRSAKey.pP );
    mPrime2Text->setText( sRSAKey.pQ );
    mExponent1Text->setText( sRSAKey.pDMP1 );
    mExponent2Text->setText( sRSAKey.pDMQ1 );
    mCoefficientText->setText( sRSAKey.pIQMP );

    ret = 0;

end :
    JS_BIN_reset( &binPri );
    JS_PKI_resetRSAKeyVal( &sRSAKey );
    if( ret != 0 ) manApplet->warningBox( tr( "failed to get key value [%1]").arg(ret), this );
}

void CreateRSAPriKeyDlg::clickUseSKI()
{
    bool bVal = mUseSKICheck->isChecked();
    mIDText->setEnabled( !bVal );
}

void CreateRSAPriKeyDlg::clickUseSPKI()
{
    bool bVal = mUseSPKICheck->isChecked();
    mPubKeyInfoText->setEnabled( !bVal );
}

void CreateRSAPriKeyDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickDecrypt()
{
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickSign()
{
    mSignCombo->setEnabled(mSignCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickSignRecover()
{
    mSignRecoverCombo->setEnabled(mSignRecoverCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickUnwrap()
{
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickSensitive()
{
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickExtractable()
{
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void CreateRSAPriKeyDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void CreateRSAPriKeyDlg::changeModules( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mModulesLenText->setText( QString("%1").arg(strLen));
}

void CreateRSAPriKeyDlg::changePubExponent( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mPubExponentLenText->setText( QString("%1").arg(strLen));
}

void CreateRSAPriKeyDlg::changePriExponent( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mPriExponentLenText->setText( QString("%1").arg(strLen));
}

void CreateRSAPriKeyDlg::changePrime1( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mPrime1LenText->setText( QString("%1").arg(strLen));
}

void CreateRSAPriKeyDlg::changePrime2( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mPrime2LenText->setText( QString("%1").arg(strLen));
}

void CreateRSAPriKeyDlg::changeExponent1( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mExponent1LenText->setText( QString("%1").arg(strLen));
}

void CreateRSAPriKeyDlg::changeExponent2( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mExponent2LenText->setText( QString("%1").arg(strLen));
}

void CreateRSAPriKeyDlg::changeCoefficient( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mCoefficientLenText->setText( QString("%1").arg(strLen));
}

void CreateRSAPriKeyDlg::setDefaults()
{
    mParamCombo->setCurrentText( "2048" );
    mEText->setText( "65537" );

//    mLabelText->setText( "RSA Private Label" );
//    mIDText->setText( "01020304" );

    mUseSKICheck->setChecked(true);
    clickUseSKI();

    QDateTime nowTime;
    nowTime.setSecsSinceEpoch( time(NULL) );

    mStartDateEdit->setDate( nowTime.date() );
    mEndDateEdit->setDate( nowTime.date() );
}

int CreateRSAPriKeyDlg::getSKI_SPKI( BIN *pSKI, BIN *pSPKI )
{
    int ret = 0;
    JRSAKeyVal  sRSAKey;
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));

    JS_PKI_setRSAKeyVal( &sRSAKey,
                         mModulesText->text().toStdString().c_str(),
                         mPubExponentText->text().toStdString().c_str(),
                         mPriExponentText->text().toStdString().c_str(),
                         mPrime1Text->text().toStdString().c_str(),
                         mPrime2Text->text().toStdString().c_str(),
                         mExponent1Text->text().toStdString().c_str(),
                         mExponent2Text->text().toStdString().c_str(),
                         mCoefficientText->text().toStdString().c_str() );

    ret = JS_PKI_encodeRSAPrivateKey( &sRSAKey, &binPri );
    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to encode private key [%1]").arg(ret));
        goto end;
    }

    ret = JS_PKI_getPubKeyFromPri( &binPri, &binPub );
    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to get public key from private key [%1]").arg(ret));
        goto end;
    }

    ret = JS_PKI_getKeyIdentifier( &binPub, pSKI );
    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to get key identifier [%1]").arg(ret));
        goto end;
    }

    JS_BIN_copy( pSPKI, &binPub );

end :
    JS_PKI_resetRSAKeyVal( &sRSAKey );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    return ret;
}
