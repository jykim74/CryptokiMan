#include "derive_key_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"
#include "common.h"
#include "cryptoki_api.h"

static QStringList sFalseTrue = { "false", "true" };
static QStringList sParamList = { "CKD_NULL", "CKD_SHA1_KDF" };

static QStringList sMechList = {
    "CKM_DH_PKCS_DERIVE", "CKM_ECDH1_DERIVE",
    "CKM_DES_ECB_ENCRYPT_DATA", "CKM_DES_CBC_ENCRYPT_DATA", "CKM_DES3_ECB_ENCRYPT_DATA", "CKM_DES3_CBC_ENCRYPT_DATA",
    "CKM_AES_ECB_ENCRYPT_DATA", "CKM_AES_CBC_ENCRYPT_DATA", "CKM_CONCATENATE_DATA_AND_BASE",
    "CKM_CONCATENATE_BASE_AND_DATA", "CKM_CONCATENATE_BASE_AND_KEY",
    "CKM_SHA1_KEY_DERIVATION", "CKM_SHA256_KEY_DERIVATION", "CKM_SHA384_KEY_DERIVATION", "CKM_SHA512_KEY_DERIVATION",
    "CKM_SHA224_KEY_DERIVATION"
};

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

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSrcLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(srcLabelChanged(int)));
    connect( mClassCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(classChanged(int)));
    connect( mSrcMethodCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeMechanism(int)));

    initialize();
    setDefaults();
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

    rv = manApplet->cryptokiAPI()->DeriveKey( session_, &sMech, hSrcKey, sTemplate, uCount, &uObj );
    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to run DeriveKey(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        freeMechanism( &sMech );
        return;
    }

    QString strHandle = QString("%1").arg( uObj );

    manApplet->messageBox(tr("success to derive key(%1)").arg(strHandle), this );
    freeMechanism( &sMech );
    QDialog::accept();
}

void DeriveKeyDlg::initAttributes()
{
    mSrcMethodCombo->addItems(sMechList);
    mClassCombo->addItems( sKeyClassList );
    mTypeCombo->addItems( sSecKeyTypeList );

    mPrivateCombo->addItems(sFalseTrue);
    mDecryptCombo->addItems(sFalseTrue);
    mSignCombo->addItems(sFalseTrue);
    mVerifyCombo->addItems(sFalseTrue);
    mUnwrapCombo->addItems(sFalseTrue);
    mSensitiveCombo->addItems(sFalseTrue);
    mWrapCombo->addItems(sFalseTrue);
    mModifiableCombo->addItems(sFalseTrue);
    mEncryptCombo->addItems(sFalseTrue);
    mDeriveCombo->addItems(sFalseTrue);
    mTokenCombo->addItems(sFalseTrue);
    mExtractableCombo->addItems(sFalseTrue);
}

void DeriveKeyDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
    mSignCombo->setEnabled(mSignCheck->isChecked());
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
    clickDerive();
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());

}

void DeriveKeyDlg::connectAttributes()
{
    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mDecryptCheck, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mUnwrapCheck, SIGNAL(clicked()), this, SLOT(clickUnwrap()));
    connect( mSignCheck, SIGNAL(clicked()), this, SLOT(clickSign()));
    connect( mWrapCheck, SIGNAL(clicked()), this, SLOT(clickWrap()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickSensitive()));
    connect( mEncryptCheck, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mVerifyCheck, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mExtractableCheck, SIGNAL(clicked()), this, SLOT(clickExtractable()));
    connect( mDeriveCheck, SIGNAL(clicked()), this, SLOT(clickDerive()));
    connect( mStartDateCheck, SIGNAL(clicked()), this, SLOT(clickStartDate()));
    connect( mEndDateCheck, SIGNAL(clicked()), this, SLOT(clickEndDate()));
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

void DeriveKeyDlg::clickSign()
{
    mSignCombo->setEnabled(mSignCheck->isChecked());
}

void DeriveKeyDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}

void DeriveKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
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
    QString strMech = mSrcMethodCombo->currentText();


    if( strMech == "CKM_ECDH1_DERIVE" )
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
    else if( strMech == "CKM_DES_CBC_ENCRYPT_DATA"
             || strMech == "CKM_DES3_CBC_ENCRYPT_DATA"
             || strMech == "CKM_AES_CBC_ENCRYPT_DATA" )
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
        mParam1Label->setText( "Parameter" );

        mParam2Label->setEnabled(false);
        mParam2Text->setEnabled(false);
        mParam2LenText->setEnabled(false);
    }
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

        JS_BIN_decodeHex( strPubData.toStdString().c_str(), &binPubData );
        ecdh1Param->public_data = binPubData.pVal;
        ecdh1Param->public_data_len = binPubData.nLen;

        if( strShare.length() > 1 )
        {
            JS_BIN_decodeHex( strShare.toStdString().c_str(), &binShare );
            ecdh1Param->shared_data = binShare.pVal;
            ecdh1Param->shared_data_len = binShare.nLen;
        }

        pPtr->pParameter = ecdh1Param;
        pPtr->ulParameterLen = sizeof( ecdh1Param );
    }
    else if( nMech == CKM_DES_ECB_ENCRYPT_DATA
             || nMech == CKM_DES3_ECB_ENCRYPT_DATA
             || nMech == CKM_AES_ECB_ENCRYPT_DATA )
    {
        BIN binData = {0,0};
        QString strData = mParam1Text->text();

        CK_KEY_DERIVATION_STRING_DATA_PTR strParam;
        strParam = (CK_KEY_DERIVATION_STRING_DATA *)JS_calloc(1, sizeof(CK_KEY_DERIVATION_STRING_DATA));

        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );
        strParam->string_data = binData.pVal;
        strParam->string_data_len = binData.nLen;

        pPtr->pParameter = strParam;
        pPtr->ulParameterLen = sizeof(strParam);
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
        desParam->data_params = binData.pVal;
        desParam->length = binData.nLen;

        pPtr->pParameter = desParam;
        pPtr->ulParameterLen = sizeof(desParam);
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
        aesParam->data_params = binData.pVal;
        aesParam->length = binData.nLen;

        pPtr->pParameter = aesParam;
        pPtr->ulParameterLen = sizeof(aesParam);
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
            if( ecdh1Param->public_data ) JS_free( ecdh1Param->public_data );
            if( ecdh1Param->shared_data ) JS_free( ecdh1Param->shared_data );
            JS_free( ecdh1Param );
        }
    }
    else if( nMech == CKM_DES_ECB_ENCRYPT_DATA
             || nMech == CKM_DES3_ECB_ENCRYPT_DATA
             || nMech == CKM_AES_ECB_ENCRYPT_DATA )
    {
        CK_KEY_DERIVATION_STRING_DATA_PTR strParam = (CK_KEY_DERIVATION_STRING_DATA *)pPtr->pParameter;

        if( strParam )
        {
            if( strParam->string_data ) JS_free( strParam->string_data );
            JS_free( strParam );
        }
    }
    else if( nMech == CKM_DES_CBC_ENCRYPT_DATA || nMech == CKM_DES3_CBC_ENCRYPT_DATA )
    {
        CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR desParam = (CK_DES_CBC_ENCRYPT_DATA_PARAMS *)pPtr->pParameter;

        if( desParam )
        {
            if( desParam->data_params ) JS_free( desParam->data_params );
            JS_free( desParam );
        }
    }
    else if( nMech == CKM_AES_CBC_ENCRYPT_DATA )
    {
        CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR aesParam = (CK_AES_CBC_ENCRYPT_DATA_PARAMS *)pPtr->pParameter;

        if( aesParam )
        {
            if( aesParam->data_params ) JS_free( aesParam->data_params );
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
