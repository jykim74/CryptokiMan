#include <QDialog>
#include <QLayout>

#include "create_pqc_pub_key_dlg.h"
#include "common.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "cryptoki_api.h"
#include "js_pki.h"
#include "js_pki_key.h"
#include "js_pqc.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"

static QStringList sFalseTrue = { "false", "true" };

CreatePQCPubKeyDlg::CreatePQCPubKeyDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    initUI();

    initAttributes();
    setAttributes();
    connectAttributes();

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

CreatePQCPubKeyDlg::~CreatePQCPubKeyDlg()
{

}

void CreatePQCPubKeyDlg::setSlotIndex(int index)
{
    slot_index_ = index;
    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    if( index >= 0 )
    {
        slot_info_ = slot_infos.at(slot_index_);
        mSlotInfoText->setText( getSlotInfo( slot_info_ ) );
        mSlotInfoText->setCursorPosition(0);
        mSlotBtn->setIcon( getSlotIcon( slot_info_ ) );
    }
}

void CreatePQCPubKeyDlg::initUI()
{
    mAlgCombo->addItems( kPQCTypeList );
    changeAlg();
}

void CreatePQCPubKeyDlg::initialize()
{
    QString strTitle;

    strTitle = tr( "Create PQC public key" );

    setWindowTitle( strTitle );

    mLabelText->setPlaceholderText( tr("String value" ));
    mSubjectText->setPlaceholderText( tr("DN value"));

    setLineEditHexOnly(mIDText, tr("Hex value"));
//    setLineEditHexOnly( mECParamsText, tr("Hex value" ));
//    setLineEditHexOnly( mECPointsText, tr("Hex value" ));
}

void CreatePQCPubKeyDlg::changeAlg()
{
    mParamCombo->clear();
    QString strAlg = mAlgCombo->currentText();

    if( strAlg == JS_PKI_KEY_NAME_ML_DSA )
        mParamCombo->addItems( kML_DSAOptionList );
    else if( strAlg == JS_PKI_KEY_NAME_ML_KEM )
        mParamCombo->addItems( kML_KEMOptionList );
    else if( strAlg == JS_PKI_KEY_NAME_SLH_DSA )
        mParamCombo->addItems( kSLH_DSAOptionList );
}

void CreatePQCPubKeyDlg::initAttributes()
{
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

void CreatePQCPubKeyDlg::setAttributes()
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

void CreatePQCPubKeyDlg::connectAttributes()
{
    connect( mAlgCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeAlg()) );

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

void CreatePQCPubKeyDlg::accept()
{
    int rv = -1;

    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();
    QString strAlg = mAlgCombo->currentText();

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL    bTrue = CK_TRUE;
    CK_BBOOL    bFalse = CK_FALSE;
    CK_OBJECT_HANDLE    hObject = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = -1;

    if( strAlg == JS_PKI_KEY_NAME_ML_DSA )
        keyType = CKK_ML_DSA;
    else if( strAlg == JS_PKI_KEY_NAME_ML_KEM )
        keyType = CKK_ML_KEM;
    else if( strAlg == JS_PKI_KEY_NAME_SLH_DSA )
        keyType = CKK_SLH_DSA;

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

    QString strKeyValue = mKeyValueText->toPlainText();
    BIN binKeyValue = {0,0};

    if( !strKeyValue.isEmpty() )
    {
        JS_BIN_decodeHex( strKeyValue.toStdString().c_str(), &binKeyValue );
        sTemplate[uCount].type = CKA_VALUE;
        sTemplate[uCount].pValue = binKeyValue.pVal;
        sTemplate[uCount].ulValueLen = binKeyValue.nLen;
        uCount++;
    }

    QString strParam = mParamCombo->currentText();

    if( !strParam.isEmpty() )
    {
        CK_ULONG parameterSet = -1;

        if( strAlg == JS_PKI_KEY_NAME_ML_DSA )
            parameterSet = getML_DSAParamType( strParam );
        else if( strAlg == JS_PKI_KEY_NAME_ML_KEM )
            parameterSet = getML_KEMParamType( strParam );
        else if( strAlg == JS_PKI_KEY_NAME_SLH_DSA )
            parameterSet = getSLH_DSAParamType( strParam );

        sTemplate[uCount].type = CKA_PARAMETER_SET;
        sTemplate[uCount].pValue = &parameterSet;
        sTemplate[uCount].ulValueLen = sizeof(parameterSet);
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

    JS_BIN_reset( &binKeyValue );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "PQC public key creation failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->clickTreeMenu( slot_index_, HM_ITEM_TYPE_PUBLICKEY );
    manApplet->messageBox( tr("PQC public key creation successful [Handle: %1]").arg( hObject ), this );
    //    manApplet->showTypeList( slot_index_, HM_ITEM_TYPE_PUBLICKEY );

    QDialog::accept();
}

void CreatePQCPubKeyDlg::clickGenKey()
{
    int ret = 0;
    BIN binPub = {0,0};
    BIN binPri = {0,0};
    JRawKeyVal sRawKey;

    QString strAlg = mAlgCombo->currentText();
    QString strParam = mParamCombo->currentText();

    int nAlg = JS_PKI_getKeyAlg( strAlg.toStdString().c_str() );
    int nParam = JS_RAW_getParam( strParam.toStdString().c_str() );

    if( nAlg < 0 || nParam < 0 )
    {
        manApplet->warningBox( tr( "Invalid algorithm" ), this );
        return;
    }

    memset( &sRawKey, 0x00, sizeof(sRawKey));

    ret = JS_PKI_genKeyPair( nAlg, nParam, 0, &binPub, &binPri );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "failed to generate keypair: %1").arg( JERR(ret)), this );
        goto end;
    }

    ret = JS_PKI_getRawKeyVal( &binPri, &sRawKey );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "failed to get raw key value: %1").arg( JERR(ret)), this );
        goto end;
    }

    mKeyValueText->setPlainText( sRawKey.pPub );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_PKI_resetRawKeyVal( &sRawKey );
}

void CreatePQCPubKeyDlg::clickUseSKI()
{
    bool bVal = mUseSKICheck->isChecked();
    mIDText->setEnabled( !bVal );
}

void CreatePQCPubKeyDlg::clickFindKey()
{
    int ret = 0;
    int nKeyType = -1;
    int nParam = -1;
    BIN binPri = {0,0};
    JRawKeyVal sRawKey;

    QString strPath;
    QString fileName = manApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.length() < 1 ) return;

    memset( &sRawKey, 0x00, sizeof(sRawKey));

    ret = JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binPri );
    if( ret < 0 )
    {
        manApplet->elog( QString( "failed to read private key [%1]").arg( ret) );
        goto end;
    }

    JS_PKI_getPriKeyAlgParam( &binPri, &nKeyType, &nParam );
    if( nKeyType != JS_PKI_KEY_TYPE_ML_DSA && nKeyType == JS_PKI_KEY_TYPE_ML_KEM && nKeyType != JS_PKI_KEY_TYPE_SLH_DSA )
    {
        manApplet->warningBox( tr("This is not a supported PQC algorithm."), this );
        goto end;
    }

    ret = JS_PKI_getRawKeyVal( &binPri, &sRawKey );
    if( ret != 0 ) goto end;

    mAlgCombo->setCurrentText( sRawKey.pAlg );
    mParamCombo->setCurrentText( sRawKey.pParam );

    mKeyValueText->setPlainText( sRawKey.pPub );

    ret = 0;

end :
    if( ret != 0 ) manApplet->warningBox( tr( "failed to get key value [%1]").arg(ret), this );

    JS_BIN_reset( &binPri );
    JS_PKI_resetRawKeyVal( &sRawKey );
}

void CreatePQCPubKeyDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void CreatePQCPubKeyDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void CreatePQCPubKeyDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void CreatePQCPubKeyDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}

void CreatePQCPubKeyDlg::clickVerifyRecover()
{
    mVerifyRecoverCombo->setEnabled(mVerifyRecoverCheck->isChecked());
}

void CreatePQCPubKeyDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void CreatePQCPubKeyDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void CreatePQCPubKeyDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void CreatePQCPubKeyDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}

void CreatePQCPubKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void CreatePQCPubKeyDlg::clickTrusted()
{
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
}

void CreatePQCPubKeyDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void CreatePQCPubKeyDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void CreatePQCPubKeyDlg::changeECPoints( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
//    mECPointsLenText->setText( QString("%1").arg(strLen));
}

void CreatePQCPubKeyDlg::changeECParams( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
//    mECParamsLenText->setText( QString("%1").arg(strLen));
}

void CreatePQCPubKeyDlg::setDefaults()
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

int CreatePQCPubKeyDlg::getSKI( BIN *pSKI )
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
//    QString strParam = mECParamsText->text();
//    QString strPoints = mECPointsText->text();
    QString strParam;
    QString strPoints;

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
