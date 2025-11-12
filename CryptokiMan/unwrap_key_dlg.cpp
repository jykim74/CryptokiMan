/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>

#include "unwrap_key_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"
#include "mech_mgr.h"
#include "hsm_man_dlg.h"
#include "object_view_dlg.h"

static QStringList sMechUnwrapSymList;
static QStringList sMechUnwrapAsymList;
static QStringList sSymTypeList;
static QStringList sAsymTypeList;

static QStringList sFalseTrue = { "false", "true" };

static QStringList sClassList = {
    "CKO_SECRET_KEY", "CKO_PRIVATE_KEY",
};




UnwrapKeyDlg::UnwrapKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;

    setupUi(this);
    initUI();

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mUnwrapTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(unwrapTypeChanged(int)));
    connect( mClassCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(classChanged(int)));
    connect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(typeChanged(int)));

    connect( mUnwrapParamText, SIGNAL(textChanged(const QString&)), this, SLOT(changeUnwrapParam(const QString&)));
    connect( mUnwrapMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(unwrapMechChanged(int)));

    connect( mReadFileBtn, SIGNAL(clicked(bool)), this, SLOT(clickReadFile()));
    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mInputText, SIGNAL(textChanged()), this, SLOT(changeInput()));

    connect( mSelectBtn, SIGNAL(clicked()), this, SLOT(clickSelect()));
    connect( mObjectViewBtn, SIGNAL(clicked()), this, SLOT(clickObjectView()));

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

UnwrapKeyDlg::~UnwrapKeyDlg()
{

}

void UnwrapKeyDlg::initUI()
{
    /* kMechWrapSymList 와 kMechWrapAsymList 는 라이선스와 상관없이 동일 함 */

    if( manApplet->isLicense() == true )
    {
        if( manApplet->settingsMgr()->useDeviceMech() == true )
        {
            sMechUnwrapSymList = manApplet->mechMgr()->getUnwrapList( MECH_TYPE_SYM );
            sMechUnwrapAsymList = manApplet->mechMgr()->getUnwrapList( MECH_TYPE_ASYM );
        }
        else
        {
            sMechUnwrapSymList = kMechWrapSymList;
            sMechUnwrapAsymList = kMechWrapAsymList;
        }
    }
    else
    {
        sMechUnwrapSymList = kMechWrapSymList;
        sMechUnwrapAsymList = kMechWrapAsymList;
    }

    sSymTypeList = kSymKeyList;
    sAsymTypeList = kAsymTypeList;

    mUnwrapMechCombo->addItems(sMechUnwrapSymList);
    mClassCombo->addItems(sClassList);
    mTypeCombo->addItems(sSymTypeList);
    mUnwrapTypeCombo->addItems( kWrapType );

    setLineEditHexOnly( mUnwrapParamText, tr("Hex value") );

    mUnwrapLabelText->setPlaceholderText( tr( "Select a key from HSM Man" ));
    mLabelText->setPlaceholderText( tr("String value" ));
    setLineEditHexOnly( mIDText, tr("Hex value" ));
    mInputText->setPlaceholderText( tr("Hex value" ));
    mUnwrapParamText->setPlaceholderText( tr("Hex value" ));
}

void UnwrapKeyDlg::initAttributes()
{
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

    mSignRecoverCombo->addItems(sFalseTrue);
    mSignRecoverCombo->setCurrentIndex(1);

    mVerifyCombo->addItems(sFalseTrue);
    mVerifyCombo->setCurrentIndex(1);

    mVerifyRecoverCombo->addItems(sFalseTrue);
    mVerifyRecoverCombo->setCurrentIndex(1);

    mTokenCombo->addItems(sFalseTrue);
    mTokenCombo->setCurrentIndex(1);

    mTrustedCombo->addItems(sFalseTrue);
    mTrustedCombo->setCurrentIndex(1);

    mExtractableCombo->addItems(sFalseTrue);
    mExtractableCombo->setCurrentIndex(1);

    mDeriveCombo->addItems(sFalseTrue);
    mDeriveCombo->setCurrentIndex(1);

    QDate nowDate = QDate::currentDate();
    mStartDateEdit->setDate(nowDate);
    mEndDateEdit->setDate(nowDate);
}

void UnwrapKeyDlg::setAttributes()
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
    mSignRecoverCombo->setEnabled(mSignRecoverCheck->isChecked());
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
    mVerifyRecoverCombo->setEnabled(mVerifyRecoverCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
    clickDerive();
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void UnwrapKeyDlg::connectAttributes()
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
    connect( mSignRecoverCheck, SIGNAL(clicked()), this, SLOT(clickSignRecover()));
    connect( mVerifyCheck, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mVerifyRecoverCheck, SIGNAL(clicked()), this, SLOT(clickVerifyRecover()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mTrustedCheck, SIGNAL(clicked()), this, SLOT(clickTrusted()));
    connect( mExtractableCheck, SIGNAL(clicked()), this, SLOT(clickExtractable()));
    connect( mDeriveCheck, SIGNAL(clicked()), this, SLOT(clickDerive()));
    connect( mStartDateCheck, SIGNAL(clicked()), this, SLOT(clickStartDate()));
    connect( mEndDateCheck, SIGNAL(clicked()), this, SLOT(clickEndDate()));
}

void UnwrapKeyDlg::setDefaults()
{
    mUseRandCheck->setChecked(true);
    clickUseRand();

    QDateTime nowTime;
    nowTime.setSecsSinceEpoch( time(NULL) );

    mStartDateEdit->setDate( nowTime.date() );
    mEndDateEdit->setDate( nowTime.date() );
}

void UnwrapKeyDlg::setSlotIndex(int index)
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

    unwrapTypeChanged(0);
//    setUnwrapLabelList();
}

void UnwrapKeyDlg::initialize()
{
    classChanged(0);
}

void UnwrapKeyDlg::accept()
{
    int rv = -1;

    QString strInput = mInputText->toPlainText();

    if( strInput.length() < 1 )
    {
        QMessageBox::warning( this, "UnwrapKey", tr("Enter wraped key value") );
        mInputText->setFocus();
        return;
    }

    CK_MECHANISM sMech;
    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE uObj = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    CK_OBJECT_CLASS objClass = 0;
    CK_KEY_TYPE keyType = 0;
    CK_OBJECT_HANDLE hUnwrappingKey = -1;

    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    if( mUnwrapObjectText->text().length() < 1 )
    {
        clickSelect();

        if( mUnwrapObjectText->text().length() < 1 )
        {
            manApplet->warningBox( tr( "Select unwrap key" ), this );
            return;
        }
    }

    hUnwrappingKey = mUnwrapObjectText->text().toLong();

    BIN binWrappedKey = {0,0};
    rv = getBINFromString( &binWrappedKey, DATA_HEX, strInput );
    if( rv < 0 )
    {
        manApplet->formatWarn( rv, this );
        return;
    }

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = JS_PKCS11_GetCKMType( mUnwrapMechCombo->currentText().toStdString().c_str());

    BIN binParam = {0,0};
    QString strParam = mUnwrapParamText->text();

    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );
        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }

    objClass = JS_PKCS11_GetCKOType( mClassCombo->currentText().toStdString().c_str());
    keyType = JS_PKCS11_GetCKKType( mTypeCombo->currentText().toStdString().c_str());

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
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    }

    if( binID.nLen > 0 )
    {
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
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

    if( mWrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_WRAP;
        sTemplate[uCount].pValue = ( mWrapCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
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

    rv = manApplet->cryptokiAPI()->UnwrapKey(
                slot_info_.getSessionHandle(),
                &sMech,
                hUnwrappingKey,
                binWrappedKey.pVal,
                binWrappedKey.nLen,
                sTemplate,
                uCount,
                &uObj );

    JS_BIN_reset( &binWrappedKey );
    JS_BIN_reset( &binParam );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "UnwrapKey execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    QString strObject = QString("%1").arg( uObj );

    if( objClass == CKO_SECRET_KEY )
        manApplet->clickTreeMenu( slot_index_, HM_ITEM_TYPE_SECRETKEY );
    else if( objClass == CKO_PRIVATE_KEY )
        manApplet->clickTreeMenu( slot_index_, HM_ITEM_TYPE_PRIVATEKEY );

    manApplet->messageBox( tr( "UnwrapKey execution successful [Object Handle: %1]" ).arg( strObject), this );
    QDialog::accept();
}


void UnwrapKeyDlg::unwrapTypeChanged(int index)
{
    mUnwrapMechCombo->clear();

    if( mUnwrapTypeCombo->currentText() == kWrapType.at(0) )
    {
        mUnwrapMechCombo->addItems( sMechUnwrapSymList );
    }
    else
    {
        mUnwrapMechCombo->addItems( sMechUnwrapAsymList );
    }

    mUnwrapLabelText->clear();
    mUnwrapObjectText->clear();
}

void UnwrapKeyDlg::unwrapMechChanged(int index )
{
    QString strMech = mUnwrapMechCombo->currentText();
    if( strMech.length() < 1 )
        mUnwrapMechText->clear();
    else
    {
        long uType = JS_PKCS11_GetCKMType( strMech.toStdString().c_str() );
        mUnwrapMechText->setText( QString( getMechHex(uType)));
    }
}

void UnwrapKeyDlg::classChanged(int index)
{
    QString strClass = mClassCombo->currentText();
    if( strClass.length() < 1 )
        mClassText->clear();
    else
    {
        long uClass = JS_PKCS11_GetCKOType( strClass.toStdString().c_str() );
        mClassText->setText( getMechHex(uClass));
    }

    mTypeCombo->clear();

    if( mClassCombo->currentText() == sClassList.at(0) )
        mTypeCombo->addItems( sSymTypeList );
    else
        mTypeCombo->addItems( sAsymTypeList );
}

void UnwrapKeyDlg::typeChanged(int index)
{
    QString strType = mTypeCombo->currentText();

    if( strType.length() < 1 )
        mTypeText->clear();
    else
    {
        long uType = JS_PKCS11_GetCKKType( strType.toStdString().c_str() );
        mTypeText->setText( getMechHex(uType));
    }
}

void UnwrapKeyDlg::clickReadFile()
{
    QString strPath;

    QString fileName = manApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    BIN binInput = {0,0};
    JS_BIN_fileRead( fileName.toLocal8Bit().toStdString().c_str(), &binInput );

    mInputText->setPlainText( getHexString( binInput.pVal, binInput.nLen ));
    JS_BIN_reset( &binInput );

}

void UnwrapKeyDlg::clickUseRand()
{
    bool bVal = mUseRandCheck->isChecked();
    mIDText->setEnabled( !bVal );
}

void UnwrapKeyDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void UnwrapKeyDlg::clickSensitive()
{
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
}

void UnwrapKeyDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void UnwrapKeyDlg::clickUnwrap()
{
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
}

void UnwrapKeyDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void UnwrapKeyDlg::clickDecrypt()
{
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
}

void UnwrapKeyDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void UnwrapKeyDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void UnwrapKeyDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}


void UnwrapKeyDlg::clickSign()
{
    mSignCombo->setEnabled(mSignCheck->isChecked());
}

void UnwrapKeyDlg::clickSignRecover()
{
    mSignRecoverCombo->setEnabled(mSignRecoverCheck->isChecked());
}

void UnwrapKeyDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}

void UnwrapKeyDlg::clickVerifyRecover()
{
    mVerifyRecoverCombo->setEnabled(mVerifyRecoverCheck->isChecked());
}

void UnwrapKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void UnwrapKeyDlg::clickTrusted()
{
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
}

void UnwrapKeyDlg::clickExtractable()
{
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
}

void UnwrapKeyDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void UnwrapKeyDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void UnwrapKeyDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void UnwrapKeyDlg::changeUnwrapParam( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mUnwrapParamLenText->setText( QString("%1").arg(strLen));
}

void UnwrapKeyDlg::clickInputClear()
{
    mInputText->clear();
}

void UnwrapKeyDlg::changeInput()
{
    QString strInput = mInputText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strInput );
    mInputLenText->setText( QString("%1").arg(strLen));
}

void UnwrapKeyDlg::clickSelect()
{
    HsmManDlg hsmMan;
    hsmMan.setSlotIndex( slot_index_ );
    hsmMan.setTitle( "Select Key" );

    if( mUnwrapTypeCombo->currentText().toUpper() == "SECRET" )
        hsmMan.setMode( HsmModeSelectSecretKey, HsmUsageUnwrap );
    else
    {
        hsmMan.setMode( HsmModeSelectPrivateKey, HsmUsageUnwrap );
        hsmMan.mPrivateTypeCombo->setCurrentText( "CKK_RSA" );
    }

    if( hsmMan.exec() == QDialog::Accepted )
    {
        mUnwrapLabelText->clear();
        mUnwrapObjectText->clear();

        QString strData = hsmMan.getData();
        QStringList listData = strData.split(":");
        if( listData.size() < 3 ) return;

        QString strType = listData.at(0);
        long hObj = listData.at(1).toLong();
        QString strID = listData.at(2);
        QString strLabel = manApplet->cryptokiAPI()->getLabel( slot_info_.getSessionHandle(), hObj );
        mUnwrapLabelText->setText( strLabel );
        mUnwrapObjectText->setText( QString("%1").arg( hObj ));
    }
}

void UnwrapKeyDlg::clickObjectView()
{
    QString strObject = mUnwrapObjectText->text();
    if( strObject.length() < 1 )
    {
        manApplet->warningBox( tr( "There is no object" ), this );
        return;
    }

    ObjectViewDlg objectView;
    objectView.setSlotIndex( slot_index_ );
    objectView.setObject( strObject.toLong() );
    objectView.exec();
}
