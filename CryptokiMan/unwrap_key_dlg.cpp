#include <QFileDialog>

#include "unwrap_key_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"
#include "common.h"

static QStringList sFalseTrue = { "false", "true" };

static QStringList sUnwrapMechList = {
    "CKM_RSA_PKCS", "CKM_RSA_PKCS_OAEP",
    "CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_PAD"
};


static QStringList sClassList = {
    "CKO_PRIVATE_KEY", "CKO_SECRET_KEY"
};


static QStringList sTypeList = {
    "CKK_RSA", "CKK_DSA", "CKK_ECDSA", "CKK_EC",
    "CKK_DES", "CKK_DES3", "CKK_AES"
};

UnwrapKeyDlg::UnwrapKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    connect( mUnwrapLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(unwrapLabelChanged(int)));
    connect( mFindBtn, SIGNAL(clicked(bool)), this, SLOT(clickFind()));

    initialize();
    setDefaults();
    setUnwrapLabelList();
}

UnwrapKeyDlg::~UnwrapKeyDlg()
{

}

void UnwrapKeyDlg::initAttributes()
{
    mUnwrapMechCombo->addItems(sUnwrapMechList);
    mClassCombo->addItems(sClassList);
    mTypeCombo->addItems(sTypeList);

    mPrivateCombo->addItems(sFalseTrue);
    mSensitiveCombo->addItems(sFalseTrue);
    mWrapCombo->addItems(sFalseTrue);
    mUnwrapCombo->addItems(sFalseTrue);
    mEncryptCombo->addItems(sFalseTrue);
    mDecryptCombo->addItems(sFalseTrue);
    mModifiableCombo->addItems(sFalseTrue);
    mSignCombo->addItems(sFalseTrue);
    mVerifyCombo->addItems(sFalseTrue);
    mTokenCombo->addItems(sFalseTrue);
    mExtractableCombo->addItems(sFalseTrue);
    mDeriveCombo->addItems(sFalseTrue);
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
    mSignCombo->setEnabled(mSignCheck->isChecked());
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
    clickDerive();
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void UnwrapKeyDlg::connectAttributes()
{
    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickSensitive()));
    connect( mWrapCheck, SIGNAL(clicked()), this, SLOT(clickWrap()));
    connect( mUnwrapCheck, SIGNAL(clicked()), this, SLOT(clickUnwrap()));
    connect( mEncryptCheck, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mDecryptCheck, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mSignCheck, SIGNAL(clicked()), this, SLOT(clickSign()));
    connect( mVerifyCheck, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mExtractableCheck, SIGNAL(clicked()), this, SLOT(clickExtractable()));
    connect( mDeriveCheck, SIGNAL(clicked()), this, SLOT(clickDerive()));
    connect( mStartDateCheck, SIGNAL(clicked()), this, SLOT(clickStartDate()));
    connect( mEndDateCheck, SIGNAL(clicked()), this, SLOT(clickEndDate()));
}

void UnwrapKeyDlg::setDefaults()
{
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

void UnwrapKeyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void UnwrapKeyDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void UnwrapKeyDlg::initialize()
{
    mSlotsCombo->clear();

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    for( int i=0; i < slot_infos.size(); i++ )
    {
        SlotInfo slotInfo = slot_infos.at(i);

        mSlotsCombo->addItem( slotInfo.getDesc() );
    }

    if( slot_infos.size() > 0 ) slotChanged(0);
}

void UnwrapKeyDlg::accept()
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    p11_ctx->hSession = slotInfo.getSessionHandle();

    int rv = -1;

    QString strWrapPath = mWrapKeyPathText->text();

    if( strWrapPath.isEmpty() )
    {
        QMessageBox::warning( this, "UnwrapKey", "You have to select wrapped file." );
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

    hUnwrappingKey = mUnwrapObjectText->text().toLong();

    BIN binWrappedKey = {0,0};
    JS_BIN_fileRead( strWrapPath.toStdString().c_str(), &binWrappedKey );

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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};
    QString strID = mIDText->text();

    if( !strID.isEmpty() )
    {
        JS_BIN_set( &binID, (unsigned char *)strID.toStdString().c_str(), strID.length() );
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

    if( mDeriveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DERIVE;
        sTemplate[uCount].pValue = ( mDeriveCombo->currentIndex() ? &bTrue : &bFalse );
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


    manApplet->logTemplate( sTemplate, uCount );
    rv = JS_PKCS11_UnwrapKey( p11_ctx, &sMech, hUnwrappingKey,
                              binWrappedKey.pVal, binWrappedKey.nLen, sTemplate, uCount, &uObj );
    manApplet->logP11Result( "C_UnwrapKey", rv );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "fail to unwrapkey(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    QString strObject = QString("%1").arg( uObj );

    manApplet->messageBox( tr("UnwrapKey is success(Object Handle:%1)").arg( strObject), this );
    QDialog::accept();
}

void UnwrapKeyDlg::unwrapLabelChanged(int index)
{
    QVariant objVal = mUnwrapLabelCombo->itemData(index);

    QString strObject = QString("%1").arg( objVal.toInt() );


    mUnwrapObjectText->setText( strObject );
}

void UnwrapKeyDlg::clickFind()
{
    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mWrapKeyPathText->setText( fileName );
}

void UnwrapKeyDlg::setUnwrapLabelList()
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    int rv = -1;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    p11_ctx->hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[1];
    CK_ULONG uCnt = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;

    objClass = CKO_SECRET_KEY;

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    manApplet->logTemplate( sTemplate, uCnt );

    rv = JS_PKCS11_FindObjectsInit( p11_ctx, sTemplate, uCnt );
    manApplet->logP11Result( "C_FindObjectsInit", rv );

    rv = JS_PKCS11_FindObjects( p11_ctx, sObjects, uMaxObjCnt, &uObjCnt );
    manApplet->logP11Result( "C_FindObjects", rv );

    rv = JS_PKCS11_FindObjectsFinal( p11_ctx );
    manApplet->logP11Result( "C_FindObjectsFinal", rv );


    mUnwrapLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = JS_PKCS11_GetAttributeValue2( p11_ctx, sObjects[i], CKA_LABEL, &binLabel );
        manApplet->logP11Result( "C_GetAttributeValue2", rv );

        JS_BIN_string( &binLabel, &pLabel );

       mUnwrapLabelCombo->addItem( pLabel, objVal );
       JS_BIN_reset(&binLabel );
       if( pLabel ) JS_free(pLabel);
    }

    uCnt = 0;
    uObjCnt = 0;
    objClass = CKO_PUBLIC_KEY;
    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    manApplet->logTemplate( sTemplate, uCnt );

    rv = JS_PKCS11_FindObjectsInit( p11_ctx, sTemplate, uCnt );
    manApplet->logP11Result( "C_FindObjectsInit", rv );

    rv = JS_PKCS11_FindObjects( p11_ctx, sObjects, uMaxObjCnt, &uObjCnt );
    manApplet->logP11Result( "C_FindObjects", rv );

    rv = JS_PKCS11_FindObjectsFinal( p11_ctx );
    manApplet->logP11Result( "C_FindObjectsFinal", rv );

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = JS_PKCS11_GetAttributeValue2( p11_ctx, sObjects[i], CKA_LABEL, &binLabel );
        manApplet->logP11Result( "C_GetAttributeValue2", rv );

        JS_BIN_string( &binLabel, &pLabel );

       mUnwrapLabelCombo->addItem( pLabel, objVal );
       JS_BIN_reset(&binLabel );
       if( pLabel ) JS_free(pLabel);
    }

    int iKeyCnt = mUnwrapLabelCombo->count();
    if( iKeyCnt > 0 )
    {
        QVariant objVal = mUnwrapLabelCombo->itemData(0);

        QString strObject = QString("%1").arg( objVal.toInt() );
        mUnwrapObjectText->setText(strObject);
    }
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

void UnwrapKeyDlg::clickSign()
{
    mSignCombo->setEnabled(mSignCheck->isChecked());
}
void UnwrapKeyDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}
void UnwrapKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
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
