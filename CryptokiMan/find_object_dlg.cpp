/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "find_object_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"
#include "mech_mgr.h"

static QStringList sFalseTrue = { "false", "true" };
static QStringList sKeyList = { "String", "Hex", "Base64" };

static QStringList sSymKeyTypeList;
static QStringList sAsymKeyTypeList;

FindObjectDlg::FindObjectDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    connect( mClassCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeClass(int)));

    connect( mFindObjectsBtn, SIGNAL(clicked()), this, SLOT(clickFindObjects()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initialize();
    setDefaults();
    tabWidget->setCurrentIndex(0);
    mFindObjectsBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

FindObjectDlg::~FindObjectDlg()
{

}

void FindObjectDlg::initialize()
{
    mSlotsCombo->clear();

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    for( int i=0; i < slot_infos.size(); i++ )
    {
        SlotInfo slotInfo = slot_infos.at(i);

        mSlotsCombo->addItem( slotInfo.getDesc() );
    }

    if( slot_infos.size() > 0 ) slotChanged(0);

    changeClass(0);
}

void FindObjectDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void FindObjectDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void FindObjectDlg::changeClass( int index )
{
    QString strClass = mClassCombo->currentText();
    long uClass = JS_PKCS11_GetCKOType( strClass.toStdString().c_str() );

    mKeyTypeCombo->clear();
    mKeyTypeCombo->addItem( "" );

    mIDLabel->setEnabled( false );
    mIDText->setEnabled( false );

    mSubjectLabel->setEnabled( false );
    mSubjectText->setEnabled( false );

    mPubKeyInfoLabel->setEnabled( false );
    mPubKeyInfoText->setEnabled( false );

    mApplicationLabel->setEnabled( false );
    mApplicationText->setEnabled( false );

    mObjectIDLabel->setEnabled( false );
    mObjectIDText->setEnabled( false );

    if( uClass == CKO_DATA )
    {
        mKeyTypeCombo->setEnabled( false );

        mApplicationLabel->setEnabled( true );
        mApplicationText->setEnabled( true );

        mObjectIDLabel->setEnabled( true );
        mObjectIDText->setEnabled( true );
    }
    else if( uClass == CKO_CERTIFICATE )
    {
        mKeyTypeCombo->setEnabled( false );

        mIDLabel->setEnabled( true );
        mIDText->setEnabled( true );
        mSubjectLabel->setEnabled( true );
        mSubjectText->setEnabled( true );
        mPubKeyInfoLabel->setEnabled( true );
        mPubKeyInfoText->setEnabled( true );
    }
    else if( uClass == CKO_SECRET_KEY )
    {
        mKeyTypeCombo->setEnabled( true );
        mKeyTypeCombo->addItems( sSymKeyTypeList );
        mIDLabel->setEnabled( true );
        mIDText->setEnabled( true );
    }
    else if( uClass == CKO_PRIVATE_KEY )
    {
        mKeyTypeCombo->setEnabled( true );
        mKeyTypeCombo->addItems( sAsymKeyTypeList );
        mIDLabel->setEnabled( true );
        mIDText->setEnabled( true );
        mPubKeyInfoLabel->setEnabled( true );
        mPubKeyInfoText->setEnabled( true );
    }
    else if( uClass == CKO_PUBLIC_KEY )
    {
        mKeyTypeCombo->setEnabled( true );
        mKeyTypeCombo->addItems( sAsymKeyTypeList );
        mIDLabel->setEnabled( true );
        mIDText->setEnabled( true );
    }
}

void FindObjectDlg::initUI()
{
    int nMaxCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    mClassCombo->addItems( kClassList );
    mMaxText->setText( QString("%1").arg( nMaxCnt ));

    if( manApplet->isLicense() == false )
    {
        sSymKeyTypeList = kSymTypeListNoLicense;
        sAsymKeyTypeList = kAsymTypeListNoLicense;
    }
    else
    {
        sSymKeyTypeList = kSymTypeList;
        sAsymKeyTypeList = kAsymTypeList;
    }

    mKeyTypeCombo->addItem( "" );
    mKeyTypeCombo->addItems( sSymKeyTypeList );
}

void FindObjectDlg::initAttributes()
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

    mVerifyCombo->addItems(sFalseTrue);
    mVerifyCombo->setCurrentIndex(1);

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

void FindObjectDlg::setAttributes()
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
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
    mDeriveCombo->setEnabled( mDeriveCheck->isChecked() );
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void FindObjectDlg::connectAttributes()
{
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
    connect( mTrustedCheck, SIGNAL(clicked()), this, SLOT(clickTrusted()));
    connect( mExtractableCheck, SIGNAL(clicked()), this, SLOT(clickExtractable()));
    connect( mDeriveCheck, SIGNAL(clicked()), this, SLOT(clickDerive()));
    connect( mStartDateCheck, SIGNAL(clicked()), this, SLOT(clickStartDate()));
    connect( mEndDateCheck, SIGNAL(clicked()), this, SLOT(clickEndDate()));
}

void FindObjectDlg::setDefaults()
{

}

void FindObjectDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void FindObjectDlg::clickSensitive()
{
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
}

void FindObjectDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void FindObjectDlg::clickUnwrap()
{
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
}

void FindObjectDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void FindObjectDlg::clickDecrypt()
{
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
}

void FindObjectDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void FindObjectDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void FindObjectDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}

void FindObjectDlg::clickSign()
{
    mSignCombo->setEnabled(mSignCheck->isChecked());
}
void FindObjectDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}
void FindObjectDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void FindObjectDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void FindObjectDlg::clickTrusted()
{
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
}

void FindObjectDlg::clickExtractable()
{
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
}

void FindObjectDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void FindObjectDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void FindObjectDlg::clickFindObjects()
{
    int rv = 0;
    int nMaxCnt = manApplet->settingsMgr()->getFindMaxObjectsCount();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[100];
    CK_ULONG uCount = 0;

    QString strClass = mClassCombo->currentText();

    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_DATE sSDate;
    CK_DATE sEDate;

    CK_OBJECT_CLASS keyClass = JS_PKCS11_GetCKOType( strClass.toStdString().c_str() );
    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &keyClass;
    sTemplate[uCount].ulValueLen = sizeof(keyClass);
    uCount++;

    BIN binLabel = {0,0};
    BIN binID = {0,0};
    BIN binApplication = {0,0};
    BIN binObjectID = {0,0};
    BIN binSubject = {0,0};
    BIN binPubKeyInfo = {0,0};

    if( keyClass == CKO_SECRET_KEY || keyClass == CKO_PRIVATE_KEY || keyClass == CKO_PUBLIC_KEY )
    {
        QString strKeyType = mKeyTypeCombo->currentText();

        if( strKeyType.length() > 1 )
        {
            CK_KEY_TYPE keyType = JS_PKCS11_GetCKKType( strKeyType.toStdString().c_str() );
            sTemplate[uCount].type = CKA_KEY_TYPE;
            sTemplate[uCount].pValue = &keyType;
            sTemplate[uCount].ulValueLen = sizeof(keyType);
            uCount++;
        }
    }

    if( keyClass == CKO_DATA )
    {
        QString strApplication = mApplicationText->text();

        if( !strApplication.isEmpty() )
        {
            JS_BIN_set( &binApplication, (unsigned char *)strApplication.toStdString().c_str(), strApplication.length() );
            sTemplate[uCount].type = CKA_APPLICATION;
            sTemplate[uCount].pValue = binApplication.pVal;
            sTemplate[uCount].ulValueLen = binApplication.nLen;
            uCount++;
        }

        QString strOID = mObjectIDText->text();

        if( !strOID.isEmpty() )
        {
            JS_BIN_decodeHex( strOID.toStdString().c_str(), &binObjectID );
            sTemplate[uCount].type = CKA_OBJECT_ID;
            sTemplate[uCount].pValue = binObjectID.pVal;
            sTemplate[uCount].ulValueLen = binObjectID.nLen;
            uCount++;
        }
    }
    else
    {
        QString strID = mIDText->text();
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
        if( binID.nLen > 0 )
        {
            sTemplate[uCount].type = CKA_ID;
            sTemplate[uCount].pValue = binID.pVal;
            sTemplate[uCount].ulValueLen = binID.nLen;
            uCount++;
        }
    }

    if( keyClass == CKO_CERTIFICATE )
    {
        QString strSubject = mSubjectText->text();
        JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );
        if( binSubject.nLen > 0 )
        {
            sTemplate[uCount].type = CKA_SUBJECT;
            sTemplate[uCount].pValue = binSubject.pVal;
            sTemplate[uCount].ulValueLen = binSubject.nLen;
            uCount++;
        }

        QString strPubKeyInfo = mPubKeyInfoText->text();
        JS_BIN_decodeHex( strPubKeyInfo.toStdString().c_str(), &binPubKeyInfo );
        if( binPubKeyInfo.nLen > 0 )
        {
            sTemplate[uCount].type = CKA_PUBLIC_KEY_INFO;
            sTemplate[uCount].pValue = binPubKeyInfo.pVal;
            sTemplate[uCount].ulValueLen = binPubKeyInfo.nLen;
            uCount++;
        }
    }
    else if( keyClass == CKO_PRIVATE_KEY )
    {
        QString strPubKeyInfo = mPubKeyInfoText->text();
        JS_BIN_decodeHex( strPubKeyInfo.toStdString().c_str(), &binPubKeyInfo );
        if( binPubKeyInfo.nLen > 0 )
        {
            sTemplate[uCount].type = CKA_PUBLIC_KEY_INFO;
            sTemplate[uCount].pValue = binPubKeyInfo.pVal;
            sTemplate[uCount].ulValueLen = binPubKeyInfo.nLen;
            uCount++;
        }
    }


    QString strLabel = mLabelText->text();

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
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

    manApplet->mainWindow()->showFindInfoList( hSession, nMaxCnt, sTemplate, uCount );

    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binApplication );
    JS_BIN_reset( &binObjectID );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binPubKeyInfo );

    QDialog::accept();
}
