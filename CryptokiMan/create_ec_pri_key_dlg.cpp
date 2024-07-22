/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "create_ec_pri_key_dlg.h"
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

CreateECPriKeyDlg::CreateECPriKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));

    initialize();
    setDefaults();

    tabWidget->setCurrentIndex(0);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CreateECPriKeyDlg::~CreateECPriKeyDlg()
{

}

void CreateECPriKeyDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void CreateECPriKeyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}


void CreateECPriKeyDlg::initialize()
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

void CreateECPriKeyDlg::initAttributes()
{
    mParamCombo->addItems( kECCOptionList );
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

void CreateECPriKeyDlg::setAttributes()
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

void CreateECPriKeyDlg::connectAttributes()
{
    connect( mGenKeyBtn, SIGNAL(clicked()), this, SLOT(clickGenKey()));
    connect( mFindKeyBtn, SIGNAL(clicked()), this, SLOT(clickFindKey()));
    connect( mUseSKICheck, SIGNAL(clicked()), this, SLOT(clickUseSKI()));
    connect( mUseSPKICheck, SIGNAL(clicked()), this, SLOT(clickUseSPKI()));

    connect( mECParamsText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECParams(const QString&)));
    connect( mKeyValueText, SIGNAL(textChanged(const QString&)), this, SLOT(changeKeyValue(const QString&)));

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

void CreateECPriKeyDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;

    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC;

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

    QString strValue = mKeyValueText->text();
    BIN binValue = {0,0};

    if( !strValue.isEmpty() )
    {
        JS_BIN_decodeHex( strValue.toStdString().c_str(), &binValue);
        sTemplate[uCount].type = CKA_VALUE;
        sTemplate[uCount].pValue = binValue.pVal;
        sTemplate[uCount].ulValueLen = binValue.nLen;
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

    JS_BIN_reset( &binECParams );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binSubject );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("EC private key creation failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("EC private key creation successful [Handle: %1]").arg( hObject ), this );
    manApplet->showTypeList( index, HM_ITEM_TYPE_PRIVATEKEY );

    QDialog::accept();
}

void CreateECPriKeyDlg::clickGenKey()
{
    int ret = 0;
    BIN binPub = {0,0};
    BIN binPri = {0,0};
    BIN binOID = {0,0};
    JECKeyVal sECKey;

    QString strParam = mParamCombo->currentText();

    JS_PKI_getOIDFromString( strParam.toStdString().c_str(), &binOID );

    memset( &sECKey, 0x00, sizeof(sECKey));

    ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
    if( ret != 0 ) goto end;

    ret = JS_PKI_getECKeyVal( &binPri, &sECKey );
    if( ret != 0 ) goto end;

    mKeyValueText->setText( sECKey.pPrivate );
    mECParamsText->setText( getHexString( binOID.pVal, binOID.nLen ));

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binOID );
    JS_PKI_resetECKeyVal( &sECKey );
}

void CreateECPriKeyDlg::clickFindKey()
{
    int ret = 0;
    int nKeyType = -1;
    BIN binPri = {0,0};
    BIN binOID = {0,0};
    JECKeyVal  sECKey;
    QString strPath = manApplet->curFile();
    QString fileName = findFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.length() < 1 ) return;

    memset( &sECKey, 0x00, sizeof(sECKey ));


    ret = JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binPri );
    if( ret < 0 )
    {
        manApplet->elog( QString( "failed to read private key [%1]").arg( ret) );
        goto end;
    }

    nKeyType = JS_PKI_getPriKeyType( &binPri );
    if( nKeyType != JS_PKI_KEY_TYPE_ECC )
    {
        manApplet->elog( QString( "invalid private key type (%1)").arg( nKeyType ));
        goto end;
    }

    ret = JS_PKI_getECKeyVal( &binPri, &sECKey );
    if( ret != 0 ) goto end;

    JS_PKI_getOIDFromString( sECKey.pCurveOID, &binOID );

    mKeyValueText->setText( sECKey.pPrivate );
    mECParamsText->setText( getHexString( binOID.pVal, binOID.nLen ));
    manApplet->setCurFile( fileName );

    ret = 0;

end :
    if( ret != 0 ) manApplet->warningBox( tr( "failed to get key value [%1]").arg(ret), this );

    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binOID );
    JS_PKI_resetECKeyVal( &sECKey );
}

void CreateECPriKeyDlg::clickUseSKI()
{
    bool bVal = mUseSKICheck->isChecked();
    mIDText->setEnabled( !bVal );
}

void CreateECPriKeyDlg::clickUseSPKI()
{
    bool bVal = mUseSPKICheck->isChecked();
    mPubKeyInfoText->setEnabled( !bVal );
}

void CreateECPriKeyDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void CreateECPriKeyDlg::clickDecrypt()
{
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
}

void CreateECPriKeyDlg::clickSign()
{
    mSignCombo->setEnabled(mSignCheck->isChecked());
}

void CreateECPriKeyDlg::clickSignRecover()
{
    mSignRecoverCombo->setEnabled(mSignRecoverCheck->isChecked());
}

void CreateECPriKeyDlg::clickUnwrap()
{
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
}

void CreateECPriKeyDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void CreateECPriKeyDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void CreateECPriKeyDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}

void CreateECPriKeyDlg::clickSensitive()
{
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
}

void CreateECPriKeyDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void CreateECPriKeyDlg::clickExtractable()
{
    mExtractableCombo->setEnabled(mExtractableCheck->isChecked());
}

void CreateECPriKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void CreateECPriKeyDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void CreateECPriKeyDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void CreateECPriKeyDlg::changeECParams( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mECParamsLenText->setText( QString("%1").arg( strLen ));
}

void CreateECPriKeyDlg::changeKeyValue( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mKeyValueLenText->setText( QString("%1").arg( strLen ));
}

void CreateECPriKeyDlg::setDefaults()
{
    mParamCombo->setCurrentText( "prime256v1" );

    mLabelText->setText( "EC Private Label" );
    mIDText->setText( "01020304" );

    mUseSKICheck->setChecked(true);
    clickUseSKI();

    QDateTime nowTime;
    nowTime.setSecsSinceEpoch( time(NULL) );

    mStartDateEdit->setDate( nowTime.date() );
    mEndDateEdit->setDate( nowTime.date() );
}

int CreateECPriKeyDlg::getSKI_SPKI( BIN *pSKI, BIN *pSPKI )
{
    int ret = 0;
    JECKeyVal sECKey;

    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binOID = {0,0};
    char sOID[128];
    QString strParam = mECParamsText->text();

    memset( &sECKey, 0x00, sizeof(sECKey));
    memset(sOID, 0x00, sizeof(sOID));

    JS_BIN_decodeHex( strParam.toStdString().c_str(), &binOID );
    ret = JS_PKI_getStringFromOID( &binOID, sOID );
    if( ret != 0 )
    {
        manApplet->elog( QString( "invalid parameters [%1]").arg(ret));
        goto end;
    }

    JS_PKI_setECKeyVal( &sECKey,
                        sOID,
                        NULL,
                        NULL,
                        mKeyValueText->text().toStdString().c_str() );

    ret = JS_PKI_encodeECPrivateKey( &sECKey, &binPri );
    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to encode private key [%1]").arg(ret));
        goto end;
    }

    ret = JS_PKI_getPubKeyFromPri( JS_PKI_KEY_TYPE_ECC, &binPri, &binPub );
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
    JS_PKI_resetECKeyVal( &sECKey );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binOID );

    return ret;
}
