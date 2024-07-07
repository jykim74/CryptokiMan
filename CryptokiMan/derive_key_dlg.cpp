/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "derive_key_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"
#include "mech_mgr.h"

static QStringList sFalseTrue = { "false", "true" };
static QStringList sParamList = { "CKD_NULL", "CKD_SHA1_KDF", "CKD_SHA224_KDF", "CKD_SHA256_KDF", "CKD_SHA348_KDF", "CKD_SHA512_KDF" };

static QStringList sMechDeriveList;

static QStringList sKeyClassList = {
    "CKO_SECRET_KEY", "CKO_PRIVATE_KEY"
};

static QStringList sPriKeyTypeList = {
    "CKK_RSA", "CKK_DH", "CKK_ECDSA", "CKK_EC", "CKK_DSA",
};

static QStringList sSecKeyTypeList = {
    "CKK_GENERIC_SECRET", "CKK_DES", "CKK_DES3", "CKK_AES"
};

DeriveKeyDlg::DeriveKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    session_ = -1;

    setupUi(this);

    initUI();
    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSrcLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(srcLabelChanged(int)));
    connect( mClassCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(classChanged(int)));
    connect( mSrcMethodCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeMechanism(int)));
    connect( mParam1Text, SIGNAL(textChanged(const QString&)), this, SLOT(changeParam1(const QString&)));
    connect( mParam2Text, SIGNAL(textChanged(const QString&)), this, SLOT(changeParam2(const QString&)));

    initialize();
    setDefaults();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

DeriveKeyDlg::~DeriveKeyDlg()
{

}

void DeriveKeyDlg::srcLabelChanged( int index )
{
    QVariant objVal = mSrcLabelCombo->itemData(index);

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mSrcObjectText->setText(strHandle);
}

void DeriveKeyDlg::classChanged( int index )
{
    mTypeCombo->clear();

    if( mClassCombo->currentIndex() == 0 )
        mTypeCombo->addItems( sSecKeyTypeList );
    else {
        mTypeCombo->addItems( sPriKeyTypeList );
    }
}

void DeriveKeyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    slot_index_ = index;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    session_ = slotInfo.getSessionHandle();
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );

    mSlotsCombo->clear();
    mSlotsCombo->addItem( slotInfo.getDesc() );
}

void DeriveKeyDlg::setSelectedSlot(int index)
{
    slotChanged( index );

    setSrcLabelList();
}

void DeriveKeyDlg::initUI()
{
    if( manApplet->isLicense() == true )
    {
        if( manApplet->settingsMgr()->useDeviceMech() == true )
        {
            sMechDeriveList = manApplet->mechMgr()->getDeriveList();
        }
        else
        {
            sMechDeriveList = kMechDeriveList;
        }
    }
    else
    {
        sMechDeriveList = kMechDeriveNoLicenseList;
    }

    mSrcMethodCombo->addItems(sMechDeriveList);
    mClassCombo->addItems( sKeyClassList );
    mTypeCombo->addItems( sSecKeyTypeList );
}

void DeriveKeyDlg::initialize()
{
    tabWidget->setCurrentIndex(0);
    mParamCombo->addItems( sParamList );
    changeMechanism(0);
}

void DeriveKeyDlg::accept()
{
    int rv = -1;

    CK_MECHANISM sMech;
    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE uObj = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = 0;
    CK_KEY_TYPE keyType = 0;
    CK_OBJECT_HANDLE hSrcKey = -1;

    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    memset( &sMech, 0x00, sizeof(sMech));


    hSrcKey = mSrcObjectText->text().toLong();
    setMechanism( &sMech );

    manApplet->log( QString( "Param[Len:%1] : %2").arg(sMech.ulParameterLen)
                    .arg( getHexString((unsigned char *)sMech.pParameter, sMech.ulParameterLen)));

    objClass = JS_PKCS11_GetCKOType( mClassCombo->currentText().toStdString().c_str() );
    keyType = JS_PKCS11_GetCKKType( mTypeCombo->currentText().toStdString().c_str() );

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strLabel = mLabelText->text();
    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};
    QString strID = mIDText->text();

    if( mUseRandCheck->isChecked() )
    {
        JS_PKI_genRandom( 20, &binID );
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

    CK_ULONG modBits = mKeySizeText->text().toLong();
    if( modBits > 0 )
    {
        sTemplate[uCount].type = CKA_VALUE_LEN;
        sTemplate[uCount].pValue = &modBits;
        sTemplate[uCount].ulValueLen = sizeof(modBits);
        uCount++;
    }

    if( mDecryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DECRYPT;
        sTemplate[uCount].pValue = ( mDecryptCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mTrustedCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TRUSTED;
        sTemplate[uCount].pValue = ( mTrustedCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mExtractableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_EXTRACTABLE;
        sTemplate[uCount].pValue = ( mExtractableCombo->currentIndex() ? &bTrue : &bFalse );
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

    rv = manApplet->cryptokiAPI()->DeriveKey( session_, &sMech, hSrcKey, sTemplate, uCount, &uObj );

    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("DeriveKey execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        freeMechanism( &sMech );
        return;
    }

    QString strHandle = QString("%1").arg( uObj );

    manApplet->messageBox(tr("DeriveKey execution successful [Handle: %1]").arg(strHandle), this );
    freeMechanism( &sMech );
    QDialog::accept();
}

void DeriveKeyDlg::initAttributes()
{
    mPrivateCombo->addItems(sFalseTrue);
    mPrivateCombo->setCurrentIndex(1);

    mDecryptCombo->addItems(sFalseTrue);
    mDecryptCombo->setCurrentIndex(1);

    mSignCombo->addItems(sFalseTrue);
    mSignCombo->setCurrentIndex(1);

    mSignRecoverCombo->addItems(sFalseTrue);
    mSignRecoverCombo->setCurrentIndex(1);

    mVerifyCombo->addItems(sFalseTrue);
    mVerifyCombo->setCurrentIndex(1);

    mVerifyRecoverCombo->addItems(sFalseTrue);
    mVerifyRecoverCombo->setCurrentIndex(1);

    mUnwrapCombo->addItems(sFalseTrue);
    mUnwrapCombo->setCurrentIndex(1);

    mSensitiveCombo->addItems(sFalseTrue);
    mSensitiveCombo->setCurrentIndex(1);

    mWrapCombo->addItems(sFalseTrue);
    mWrapCombo->setCurrentIndex(1);

    mModifiableCombo->addItems(sFalseTrue);
    mModifiableCombo->setCurrentIndex(1);

    mCopyableCombo->addItems(sFalseTrue);
    mCopyableCombo->setCurrentIndex(1);

    mDestroyableCombo->addItems(sFalseTrue);
    mDestroyableCombo->setCurrentIndex(1);

    mEncryptCombo->addItems(sFalseTrue);
    mEncryptCombo->setCurrentIndex(1);

    mDeriveCombo->addItems(sFalseTrue);
    mDeriveCombo->setCurrentIndex(1);

    mTokenCombo->addItems(sFalseTrue);
    mTokenCombo->setCurrentIndex(1);

    mTrustedCombo->addItems(sFalseTrue);
    mTrustedCombo->setCurrentIndex(1);

    mExtractableCombo->addItems(sFalseTrue);
    mExtractableCombo->setCurrentIndex(1);
}

void DeriveKeyDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
    mSignCombo->setEnabled(mSignCheck->isChecked());
    mSignRecoverCombo->setEnabled(mSignRecoverCheck->isChecked());
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
    mVerifyRecoverCombo->setEnabled(mVerifyRecoverCheck->isChecked());
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
    clickDerive();
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());

}

void DeriveKeyDlg::connectAttributes()
{
    connect( mUseRandCheck, SIGNAL(clicked()), this, SLOT(clickUseRand()));
    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mDecryptCheck, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mUnwrapCheck, SIGNAL(clicked()), this, SLOT(clickUnwrap()));
    connect( mSignCheck, SIGNAL(clicked()), this, SLOT(clickSign()));
    connect( mSignRecoverCheck, SIGNAL(clicked()), this, SLOT(clickSignRecover()));
    connect( mWrapCheck, SIGNAL(clicked()), this, SLOT(clickWrap()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mCopyableCheck, SIGNAL(clicked()), this, SLOT(clickCopyable()));
    connect( mDestroyableCheck, SIGNAL(clicked()), this, SLOT(clickDestroyable()));
    connect( mSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickSensitive()));
    connect( mEncryptCheck, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mTrustedCheck, SIGNAL(clicked()), this, SLOT(clickTrusted()));
    connect( mVerifyCheck, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mVerifyRecoverCheck, SIGNAL(clicked()), this, SLOT(clickVerifyRecover()));
    connect( mExtractableCheck, SIGNAL(clicked()), this, SLOT(clickExtractable()));
    connect( mDeriveCheck, SIGNAL(clicked()), this, SLOT(clickDerive()));
    connect( mStartDateCheck, SIGNAL(clicked()), this, SLOT(clickStartDate()));
    connect( mEndDateCheck, SIGNAL(clicked()), this, SLOT(clickEndDate()));
}

void DeriveKeyDlg::clickUseRand()
{
    bool bVal = mUseRandCheck->isChecked();
    mIDText->setEnabled( !bVal );
}

void DeriveKeyDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void DeriveKeyDlg::clickSensitive()
{
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
}

void DeriveKeyDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void DeriveKeyDlg::clickUnwrap()
{
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
}

void DeriveKeyDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void DeriveKeyDlg::clickDecrypt()
{
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
}

void DeriveKeyDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void DeriveKeyDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void DeriveKeyDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}

void DeriveKeyDlg::clickSign()
{
    mSignCombo->setEnabled(mSignCheck->isChecked());
}

void DeriveKeyDlg::clickSignRecover()
{
    mSignRecoverCombo->setEnabled(mSignRecoverCheck->isChecked());
}

void DeriveKeyDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}

void DeriveKeyDlg::clickVerifyRecover()
{
    mVerifyRecoverCombo->setEnabled(mVerifyRecoverCheck->isChecked());
}

void DeriveKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void DeriveKeyDlg::clickTrusted()
{
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
}

void DeriveKeyDlg::clickExtractable()
{
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
}

void DeriveKeyDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void DeriveKeyDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void DeriveKeyDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void DeriveKeyDlg::changeMechanism( int index )
{
    long nMech = JS_PKCS11_GetCKMType( mSrcMethodCombo->currentText().toStdString().c_str());

    if( nMech == CKM_ECDH1_DERIVE )
    {
        mParamComboLabel->setEnabled(true);
        mParamComboLabel->setText( "EC_KDF_T" );
        mParamCombo->setEnabled(true);

        mParam1Label->setText( "Public Data" );

        mParam2Label->setText( "Shared Data" );
        mParam2Label->setEnabled(true);
        mParam2Text->setEnabled( true );
        mParam2LenText->setEnabled( true );
    }
    else if( nMech == CKM_DES_CBC_ENCRYPT_DATA
             || nMech == CKM_DES3_CBC_ENCRYPT_DATA
             || nMech == CKM_AES_CBC_ENCRYPT_DATA
             || nMech == CKM_CONCATENATE_BASE_AND_DATA
             || nMech == CKM_CONCATENATE_DATA_AND_BASE )
    {
        mParamCombo->setEnabled(false);
        mParamComboLabel->setEnabled(false);

        mParam1Label->setText( "IV" );

        mParam2Label->setText( "Data Params" );
        mParam2Label->setEnabled(true);
        mParam2Text->setEnabled( true );
        mParam2LenText->setEnabled( true );
    }
    else
    {
        mParamCombo->setEnabled(false);
        mParamComboLabel->setEnabled(false);
        mParam1Label->setText( tr("Parameter") );

        mParam2Label->setEnabled(false);
        mParam2Text->setEnabled(false);
        mParam2LenText->setEnabled(false);
    }
}

void DeriveKeyDlg::changeParam1( const QString& text )
{
    int nLen = text.length() / 2;

    mParam1LenText->setText( QString("%1").arg( nLen ));
}

void DeriveKeyDlg::changeParam2( const QString& text )
{
    int nLen = text.length() / 2;

    mParam2LenText->setText( QString("%1").arg( nLen ));
}

void DeriveKeyDlg::setMechanism( void *pMech )
{
    if( pMech == NULL ) return;
    CK_MECHANISM_PTR pPtr = (CK_MECHANISM *)pMech;
    long nMech = JS_PKCS11_GetCKMType( mSrcMethodCombo->currentText().toStdString().c_str());

    pPtr->mechanism = nMech;

    if( nMech == CKM_ECDH1_DERIVE )
    {
        BIN binShare = {0,0};
        BIN binPubData = {0,0};

        QString strPubData = mParam1Text->text();
        QString strShare = mParam2Text->text();
        QString strParam  = mParamCombo->currentText();


        CK_ECDH1_DERIVE_PARAMS_PTR ecdh1Param;
        ecdh1Param = (CK_ECDH1_DERIVE_PARAMS *)JS_calloc( 1, sizeof(CK_ECDH1_DERIVE_PARAMS));

        if( strParam == "CKD_NULL" )
            ecdh1Param->kdf = CKD_NULL;
        else if( strParam == "CKD_SHA1_KDF" )
            ecdh1Param->kdf = CKD_SHA1_KDF;
        else if( strParam == "CKD_SHA224_KDF" )
            ecdh1Param->kdf = CKD_SHA224_KDF;
        else if( strParam == "CKD_SHA256_KDF" )
            ecdh1Param->kdf = CKD_SHA256_KDF;
        else if( strParam == "CKD_SHA384_KDF" )
            ecdh1Param->kdf = CKD_SHA384_KDF;
        else if( strParam == "CKD_SHA512_KDF" )
            ecdh1Param->kdf = CKD_SHA512_KDF;

        JS_BIN_decodeHex( strPubData.toStdString().c_str(), &binPubData );
        ecdh1Param->pPublicData = binPubData.pVal;
        ecdh1Param->ulPublicDataLen = binPubData.nLen;

        if( strShare.length() > 1 )
        {
            JS_BIN_decodeHex( strShare.toStdString().c_str(), &binShare );
            ecdh1Param->pSharedData = binShare.pVal;
            ecdh1Param->ulSharedDataLen = binShare.nLen;
        }

        pPtr->pParameter = ecdh1Param;
        pPtr->ulParameterLen = sizeof( CK_ECDH1_DERIVE_PARAMS );
    }
    else if( nMech == CKM_DES_ECB_ENCRYPT_DATA
             || nMech == CKM_DES3_ECB_ENCRYPT_DATA
             || nMech == CKM_AES_ECB_ENCRYPT_DATA
             || nMech == CKM_CONCATENATE_BASE_AND_DATA
             || nMech == CKM_CONCATENATE_DATA_AND_BASE )
    {
        BIN binData = {0,0};
        QString strData = mParam1Text->text();

        CK_KEY_DERIVATION_STRING_DATA_PTR strParam;
        strParam = (CK_KEY_DERIVATION_STRING_DATA *)JS_calloc(1, sizeof(CK_KEY_DERIVATION_STRING_DATA));

        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );
        strParam->pData = binData.pVal;
        strParam->ulLen = binData.nLen;

        pPtr->pParameter = strParam;
        pPtr->ulParameterLen = sizeof(CK_KEY_DERIVATION_STRING_DATA);
    }
    else if( nMech == CKM_DES_CBC_ENCRYPT_DATA || nMech == CKM_DES3_CBC_ENCRYPT_DATA )
    {
        BIN binIV = {0,0};
        BIN binData = {0,0};

        QString strIV = mParam1Text->text();
        QString strData = mParam2Text->text();

        CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR desParam;
        desParam = (CK_DES_CBC_ENCRYPT_DATA_PARAMS *)JS_calloc(1, sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS));

        JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );

        memcpy( desParam->iv, binIV.pVal, binIV.nLen < 8 ? binIV.nLen : 8 );
        desParam->pData = binData.pVal;
        desParam->length = binData.nLen;

        pPtr->pParameter = desParam;
        pPtr->ulParameterLen = sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS);
    }
    else if( nMech == CKM_AES_CBC_ENCRYPT_DATA )
    {
        BIN binIV = {0,0};
        BIN binData = {0,0};

        QString strIV = mParam1Text->text();
        QString strData = mParam2Text->text();

        CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR aesParam;
        aesParam = (CK_AES_CBC_ENCRYPT_DATA_PARAMS *)JS_calloc(1, sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS));

        JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );

        memcpy( aesParam->iv, binIV.pVal, binIV.nLen < 16 ? binIV.nLen : 16 );
        aesParam->pData = binData.pVal;
        aesParam->length = binData.nLen;

        pPtr->pParameter = aesParam;
        pPtr->ulParameterLen = sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS);
    }
    else
    {
        BIN binParam = {0,0};
        QString strParam = mParam1Text->text();
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );

        pPtr->pParameter = binParam.pVal;
        pPtr->ulParameterLen = binParam.nLen;
    }
}

void DeriveKeyDlg::freeMechanism( void *pMech )
{
    if( pMech == NULL ) return;
    CK_MECHANISM_PTR pPtr = (CK_MECHANISM *)pMech;
    long nMech = pPtr->mechanism;

    if( nMech == CKM_ECDH1_DERIVE )
    {
        CK_ECDH1_DERIVE_PARAMS_PTR ecdh1Param = (CK_ECDH1_DERIVE_PARAMS *)pPtr->pParameter;

        if( ecdh1Param )
        {
            if( ecdh1Param->pPublicData ) JS_free( ecdh1Param->pPublicData );
            if( ecdh1Param->pSharedData ) JS_free( ecdh1Param->pSharedData );
            JS_free( ecdh1Param );
        }
    }
    else if( nMech == CKM_DES_ECB_ENCRYPT_DATA
             || nMech == CKM_DES3_ECB_ENCRYPT_DATA
             || nMech == CKM_AES_ECB_ENCRYPT_DATA
             || nMech == CKM_CONCATENATE_BASE_AND_DATA
             || nMech == CKM_CONCATENATE_DATA_AND_BASE )
    {
        CK_KEY_DERIVATION_STRING_DATA_PTR strParam = (CK_KEY_DERIVATION_STRING_DATA *)pPtr->pParameter;

        if( strParam )
        {
            if( strParam->pData ) JS_free( strParam->pData );
            JS_free( strParam );
        }
    }
    else if( nMech == CKM_DES_CBC_ENCRYPT_DATA || nMech == CKM_DES3_CBC_ENCRYPT_DATA )
    {
        CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR desParam = (CK_DES_CBC_ENCRYPT_DATA_PARAMS *)pPtr->pParameter;

        if( desParam )
        {
            if( desParam->pData ) JS_free( desParam->pData );
            JS_free( desParam );
        }
    }
    else if( nMech == CKM_AES_CBC_ENCRYPT_DATA )
    {
        CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR aesParam = (CK_AES_CBC_ENCRYPT_DATA_PARAMS *)pPtr->pParameter;

        if( aesParam )
        {
            if( aesParam->pData ) JS_free( aesParam->pData );
            JS_free( aesParam );
        }
    }
    else
    {
        if( pPtr->pParameter ) JS_free( pPtr->pParameter );
    }

    pPtr->pParameter = NULL;
    pPtr->ulParameterLen = 0;
}

void DeriveKeyDlg::setSrcLabelList()
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[10];
    CK_ULONG uCnt = 0;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE sObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;


    objClass = CKO_SECRET_KEY;

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_DERIVE;
    sTemplate[uCnt].pValue = &kTrue;
    sTemplate[uCnt].ulValueLen = sizeof(CK_BBOOL);
    uCnt++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
    if( rv != CKR_OK ) return;

    mSrcLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pStr = NULL;
        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

        JS_BIN_string( &binLabel, &pStr );

        mSrcLabelCombo->addItem( pStr, objVal );
        if( pStr ) JS_free(pStr);
        JS_BIN_reset( &binLabel );
    }

    uCnt = 0;
    uObjCnt = 0;

    objClass = CKO_PRIVATE_KEY;
    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_DERIVE;
    sTemplate[uCnt].pValue = &kTrue;
    sTemplate[uCnt].ulValueLen = sizeof(CK_BBOOL);
    uCnt++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
    if( rv != CKR_OK ) return;

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pStr = NULL;
        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

        JS_BIN_string( &binLabel, &pStr );

        mSrcLabelCombo->addItem( pStr, objVal );
        if( pStr ) JS_free(pStr);
        JS_BIN_reset( &binLabel );
    }

    int iKeyCnt = mSrcLabelCombo->count();
    if( iKeyCnt > 0 )
    {
        QVariant objVal = mSrcLabelCombo->itemData(0);

        QString strHandle = QString("%1").arg( objVal.toInt() );
        mSrcObjectText->setText( strHandle );
    }
}

void DeriveKeyDlg::setDefaults()
{
    mUseRandCheck->setChecked(true);
    clickUseRand();

    /*
    mPrivateCheck->setChecked(true);
    mPrivateCombo->setEnabled(true);
    mPrivateCombo->setCurrentIndex(1);

    mEncryptCheck->setChecked(true);
    mEncryptCombo->setEnabled(true);
    mEncryptCombo->setCurrentIndex(1);

    mDecryptCheck->setChecked(true);
    mDecryptCombo->setEnabled(true);
    mDecryptCombo->setCurrentIndex(1);

    mTokenCheck->setChecked(true);
    mTokenCombo->setEnabled(true);
    mTokenCombo->setCurrentIndex(1);
    */

    QDateTime nowTime;
    nowTime.setSecsSinceEpoch( time(NULL) );

    mStartDateEdit->setDate( nowTime.date() );
    mEndDateEdit->setDate( nowTime.date() );
}
