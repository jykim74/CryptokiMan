/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "gen_key_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"
#include "mech_mgr.h"

static QStringList sMechGenList;

static QStringList sFalseTrue = { "false", "true" };
static QStringList sParamList = { "String", "Hex", "Base64" };

GenKeyDlg::GenKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mParamCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeParam()));
    connect( mParamText, SIGNAL(textChanged()), this, SLOT(changeParam()));
    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));

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

GenKeyDlg::~GenKeyDlg()
{

}

void GenKeyDlg::setSlotIndex(int index)
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

void GenKeyDlg::mechChanged( int index )
{
    QString strMech = mMechCombo->currentText();
    int uMech = JS_PKCS11_GetCKMType( strMech.toStdString().c_str() );
    mMechText->setText( QString( getMechHex(uMech )));

}

void GenKeyDlg::initUI()
{
    if( manApplet->isLicense() )
    {
        if( manApplet->settingsMgr()->useDeviceMech() )
        {
            sMechGenList = manApplet->mechMgr()->getGenerateList();
        }
        else
        {
            sMechGenList = kMechGenList;
        }
    }
    else
    {
        sMechGenList = kMechGenList;
    }

    mMechCombo->addItems(sMechGenList);
}

void GenKeyDlg::initialize()
{
    mechChanged(0);
}

void GenKeyDlg::initAttributes()
{
    mParamCombo->addItems(sParamList);

    mPrivateCombo->addItems(sFalseTrue);
    mPrivateCombo->setCurrentIndex(1);

    mSensitiveCombo->addItems(sFalseTrue);
    mSensitiveCombo->setCurrentIndex(1);

    mWrapCombo->addItems(sFalseTrue);
    mWrapCombo->setCurrentIndex(1);

    mUnwrapCombo->addItems(sFalseTrue);
    mUnwrapCombo->setCurrentIndex(1);

    mEncryptCombo->addItems(sFalseTrue);
    mEncryptCombo->setCurrentIndex(1);

    mDecryptCombo->addItems(sFalseTrue);
    mDecryptCombo->setCurrentIndex(1);

    mModifiableCombo->addItems(sFalseTrue);
    mModifiableCombo->setCurrentIndex(1);

    mCopyableCombo->addItems(sFalseTrue);
    mCopyableCombo->setCurrentIndex(1);

    mDestroyableCombo->addItems(sFalseTrue);
    mDestroyableCombo->setCurrentIndex(1);

    mSignCombo->addItems(sFalseTrue);
    mSignCombo->setCurrentIndex(1);

    mVerifyCombo->addItems(sFalseTrue);
    mVerifyCombo->setCurrentIndex(1);

    mTokenCombo->addItems(sFalseTrue);
    mTokenCombo->setCurrentIndex(1);

    mDeriveCombo->addItems(sFalseTrue);
    mDeriveCombo->setCurrentIndex(1);

    mTrustedCombo->addItems(sFalseTrue);
    mTrustedCombo->setCurrentIndex(1);

    mExtractableCombo->addItems(sFalseTrue);
    mExtractableCombo->setCurrentIndex(1);

    QDate nowDate = QDate::currentDate();
    mStartDateEdit->setDate(nowDate);
    mEndDateEdit->setDate(nowDate);
}

void GenKeyDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
    mSignCombo->setEnabled(mSignCheck->isChecked());
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
    mDeriveCombo->setEnabled( mDeriveCheck->isChecked() );
    mTrustedCombo->setEnabled( mTrustedCheck->isChecked() );
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void GenKeyDlg::connectAttributes()
{
    connect( mUseRandCheck, SIGNAL(clicked()), this, SLOT(clickUseRand()));
    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickSensitive()));
    connect( mWrapCheck, SIGNAL(clicked()), this, SLOT(clickWrap()));
    connect( mUnwrapCheck, SIGNAL(clicked()), this, SLOT(clickUnwrap()));
    connect( mEncryptCheck, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mDecryptCheck, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mCopyableCheck, SIGNAL(clicked()), this, SLOT(clickCopyable()));
    connect( mDestroyableCheck, SIGNAL(clicked()), this, SLOT(clickDestroyable()));
    connect( mSignCheck, SIGNAL(clicked()), this, SLOT(clickSign()));
    connect( mVerifyCheck, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mExtractableCheck, SIGNAL(clicked()), this, SLOT(clickExtractable()));
    connect( mDeriveCheck, SIGNAL(clicked()), this, SLOT(clickDerive()));
    connect( mTrustedCheck, SIGNAL(clicked()), this, SLOT(clickTrusted()));
    connect( mStartDateCheck, SIGNAL(clicked()), this, SLOT(clickStartDate()));
    connect( mEndDateCheck, SIGNAL(clicked()), this, SLOT(clickEndDate()));
}

void GenKeyDlg::accept()
{
    int rv = -1;
    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = 0;
    CK_MECHANISM    sMech;

    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_DATE sSDate;
    CK_DATE sEDate;

    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();
    memset( &sMech, 0x00, sizeof(sMech) );
    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    sMech.mechanism = JS_PKCS11_GetCKMType( mMechCombo->currentText().toStdString().c_str() );
    BIN binParam = {0,0};

    QString strParam = mParamText->toPlainText();
    if( !strParam.isEmpty() )
    {
        if( mParamCombo->currentIndex() == 0 )
            JS_BIN_set( &binParam, (unsigned char *)strParam.toStdString().c_str(), strParam.length() );
        else if( mParamCombo->currentIndex() == 1 )
            JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );
        else if( mParamCombo->currentIndex() == 2 )
            JS_BIN_decodeBase64( strParam.toStdString().c_str(), &binParam );

        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &keyClass;
    sTemplate[uCount].ulValueLen = sizeof(keyClass);
    uCount++;

    /*
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;
    */

    BIN binLabel = {0,0};
    QString strLabel = mLabelText->text();

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
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
        QString strID = mIDText->text();
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

    if( mTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = ( mTokenCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mTrustedCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TRUSTED;
        sTemplate[uCount].pValue = ( mTrustedCombo->currentIndex() ? &bTrue : &bFalse );
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

    rv = manApplet->cryptokiAPI()->GenerateKey( hSession, &sMech, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binParam );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("GenerateKey execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr( "GenerateKey execution successful" ), this );
    manApplet->showTypeList( slot_index_, HM_ITEM_TYPE_SECRETKEY );

    QDialog::accept();
}

void GenKeyDlg::clickUseRand()
{
    bool bVal = mUseRandCheck->isChecked();

    mIDText->setEnabled( !bVal );
}

void GenKeyDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void GenKeyDlg::clickSensitive()
{
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
}

void GenKeyDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void GenKeyDlg::clickUnwrap()
{
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
}

void GenKeyDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void GenKeyDlg::clickDecrypt()
{
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
}

void GenKeyDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void GenKeyDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void GenKeyDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}

void GenKeyDlg::clickSign()
{
    mSignCombo->setEnabled(mSignCheck->isChecked());
}
void GenKeyDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}
void GenKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void GenKeyDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void GenKeyDlg::clickTrusted()
{
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
}

void GenKeyDlg::clickExtractable()
{
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
}

void GenKeyDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void GenKeyDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void GenKeyDlg::changeParam()
{
    QString strParam = mParamText->toPlainText();

    QString strLen = getDataLenString( mParamCombo->currentText(), strParam );
    mParamLenText->setText( QString("%1").arg(strLen));
}

void GenKeyDlg::setDefaults()
{
    mLabelText->setText( "Secret key Label" );

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

    mKeySizeText->setText( "16" );

    QDateTime nowTime;
    nowTime.setSecsSinceEpoch( time(NULL) );

    mStartDateEdit->setDate( nowTime.date() );
    mEndDateEdit->setDate( nowTime.date() );
}
