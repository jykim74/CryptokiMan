#include "mainwindow.h"
#include "man_applet.h"
#include "copy_object_dlg.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"
#include "mech_mgr.h"

static QStringList sFalseTrue = { "false", "true" };

CopyObjectDlg::CopyObjectDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    session_ = -1;

    setupUi(this);

    initUI();

    connect( mSrcTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeSrcType(int)));
    connect( mSrcLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeSrcLabel(int)));

    initAttributes();
    setAttributes();
    connectAttributes();

    initialize();
    setDefaults();

    tabWidget->setCurrentIndex(0);
}

CopyObjectDlg::~CopyObjectDlg()
{

}

void CopyObjectDlg::initUI()
{
    mSrcTypeCombo->addItems( kObjectTypeList );
}

void CopyObjectDlg::slotChanged(int index)
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

void CopyObjectDlg::setSelectedSlot(int index)
{
    slotChanged( index );
    changeSrcType(0);
}

void CopyObjectDlg::initialize()
{

}

void CopyObjectDlg::initAttributes()
{
    mPrivateCombo->addItems(sFalseTrue);
    mSensitiveCombo->addItems(sFalseTrue);
    mWrapCombo->addItems(sFalseTrue);
    mUnwrapCombo->addItems(sFalseTrue);
    mEncryptCombo->addItems(sFalseTrue);
    mDecryptCombo->addItems(sFalseTrue);
    mModifiableCombo->addItems(sFalseTrue);
    mCopyableCombo->addItems(sFalseTrue);
    mDestroyableCombo->addItems(sFalseTrue);
    mSignCombo->addItems(sFalseTrue);
    mSignRecoverCombo->addItems(sFalseTrue);
    mVerifyCombo->addItems(sFalseTrue);
    mVerifyRecoverCombo->addItems(sFalseTrue);
    mTokenCombo->addItems(sFalseTrue);
    mTrustedCombo->addItems(sFalseTrue);
    mExtractableCombo->addItems(sFalseTrue);
    mDeriveCombo->addItems(sFalseTrue);

    QDate nowDate = QDate::currentDate();
    mStartDateEdit->setDate(nowDate);
    mEndDateEdit->setDate(nowDate);
}

void CopyObjectDlg::setAttributes()
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

void CopyObjectDlg::connectAttributes()
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

void CopyObjectDlg::setDefaults()
{
    mUseRandCheck->setChecked(true);
    clickUseRand();

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

    QDateTime nowTime;
    nowTime.setTime_t( time(NULL) );

    mStartDateEdit->setDate( nowTime.date() );
    mEndDateEdit->setDate( nowTime.date() );
}

void CopyObjectDlg::accept()
{
    int rv = -1;

    QString strSrcObject = mSrcObjectText->text();
    int index = mSlotsCombo->currentIndex();

    if( strSrcObject.toInt() <= 0  )
    {
        QMessageBox::warning( this, "Copy Object", tr("There is no object handler") );
        return;
    }

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE uNewObj = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

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
        getCKDate( mStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mEndDateCheck->isChecked() )
    {
        getCKDate( mEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CopyObject( session_, strSrcObject.toLong(), sTemplate, uCount, &uNewObj );

    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "fail to run CopyObject(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    QString strNewObject = QString("%1").arg( uNewObj );
    QString strSrcType = mSrcTypeCombo->currentText();

    manApplet->messageBox( tr("CopyObject is success(New Object Handle:%1)").arg( strNewObject), this );

    if( strSrcType == kCertificate )
        manApplet->showTypeList( index, HM_ITEM_TYPE_CERTIFICATE );
    else if( strSrcType == kPublicKey )
        manApplet->showTypeList( index, HM_ITEM_TYPE_PUBLICKEY );
    else if( strSrcType == kPrivateKey )
        manApplet->showTypeList( index, HM_ITEM_TYPE_PRIVATEKEY );
    else if( strSrcType == kSecretKey )
        manApplet->showTypeList( index, HM_ITEM_TYPE_SECRETKEY );
    else if( strSrcType == kData )
        manApplet->showTypeList( index, HM_ITEM_TYPE_DATA );

    QDialog::accept();
}

void CopyObjectDlg::changeSrcType( int index )
{
    mSrcLabelCombo->clear();
    QString strType = mSrcTypeCombo->currentText();

    if( strType == "SecretKey" )
        readSrcSecretKeyLabels();
    else if( strType == "PublicKey" )
        readSrcPublicKeyLabels();
    else if( strType == "PrivateKey" )
        readSrcPrivateKeyLabels();
    else if( strType == "Certificate" )
        readSrcCertificateLabels();
    else if( strType == "Data" )
        readSrcDataLabels();
}

void CopyObjectDlg::changeSrcLabel( int index )
{
    QVariant objVal = mSrcLabelCombo->itemData(index);
    mSrcObjectText->setText( QString( "%1" ).arg( objVal.toUInt()));
}

void CopyObjectDlg::readSrcLabels( CK_OBJECT_CLASS objClass )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[10];
    CK_ULONG uCnt = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;

//    CK_OBJECT_CLASS objClass = 0;
//    objClass = CKO_SECRET_KEY;

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_COPYABLE;
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
        char *pLabel = NULL;

        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

        JS_BIN_string( &binLabel, &pLabel );

        mSrcLabelCombo->addItem( pLabel, objVal );

        if( pLabel ) JS_free( pLabel );
        JS_BIN_reset( &binLabel );
    }

    int iKeyCnt = mSrcLabelCombo->count();
    if( iKeyCnt > 0 )
    {
        QVariant objVal = mSrcLabelCombo->itemData(0);
        QString strObject = QString("%1").arg( objVal.toInt() );

        mSrcObjectText->setText( strObject );
    }
    else
    {
        mSrcObjectText->clear();
    }
}

void CopyObjectDlg::readSrcSecretKeyLabels()
{
    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_SECRET_KEY;

    readSrcLabels( objClass );
}

void CopyObjectDlg::readSrcPrivateKeyLabels()
{
    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_PRIVATE_KEY;

    readSrcLabels( objClass );
}

void CopyObjectDlg::readSrcPublicKeyLabels()
{
    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_PUBLIC_KEY;

    readSrcLabels( objClass );
}

void CopyObjectDlg::readSrcCertificateLabels()
{
    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_CERTIFICATE;

    readSrcLabels( objClass );
}

void CopyObjectDlg::readSrcDataLabels()
{
    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_DATA;

    readSrcLabels( objClass );
}

void CopyObjectDlg::clickUseRand()
{
    bool bVal = mUseRandCheck->isChecked();
    mIDText->setEnabled( !bVal );
}

void CopyObjectDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void CopyObjectDlg::clickSensitive()
{
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
}

void CopyObjectDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void CopyObjectDlg::clickUnwrap()
{
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
}

void CopyObjectDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void CopyObjectDlg::clickDecrypt()
{
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
}

void CopyObjectDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void CopyObjectDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void CopyObjectDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}


void CopyObjectDlg::clickSign()
{
    mSignCombo->setEnabled(mSignCheck->isChecked());
}

void CopyObjectDlg::clickSignRecover()
{
    mSignRecoverCombo->setEnabled(mSignRecoverCheck->isChecked());
}

void CopyObjectDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}

void CopyObjectDlg::clickVerifyRecover()
{
    mVerifyRecoverCombo->setEnabled(mVerifyRecoverCheck->isChecked());
}

void CopyObjectDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void CopyObjectDlg::clickTrusted()
{
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
}

void CopyObjectDlg::clickExtractable()
{
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
}

void CopyObjectDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void CopyObjectDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void CopyObjectDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}
