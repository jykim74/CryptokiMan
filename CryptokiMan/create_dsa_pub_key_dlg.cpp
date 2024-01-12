#include "create_dsa_pub_key_dlg.h"
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

CreateDSAPubKeyDlg::CreateDSAPubKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));

    connect( mPText, SIGNAL(textChanged(const QString&)), this, SLOT(changeP(const QString&)));
    connect( mQText, SIGNAL(textChanged(const QString&)), this, SLOT(changeQ(const QString&)));
    connect( mGText, SIGNAL(textChanged(const QString&)), this, SLOT(changeG(const QString&)));
    connect( mPublicText, SIGNAL(textChanged(const QString&)), this, SLOT(changePublic(const QString&)));

    initialize();
    setDefaults();

    tabWidget->setCurrentIndex(0);
}

CreateDSAPubKeyDlg::~CreateDSAPubKeyDlg()
{

}

void CreateDSAPubKeyDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void CreateDSAPubKeyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}


void CreateDSAPubKeyDlg::initialize()
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

void CreateDSAPubKeyDlg::initAttributes()
{
    mParamCombo->addItems( kDSAOptionList );
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

void CreateDSAPubKeyDlg::setAttributes()
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

void CreateDSAPubKeyDlg::connectAttributes()
{
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

void CreateDSAPubKeyDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;

    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL    bTrue = CK_TRUE;
    CK_BBOOL    bFalse = CK_FALSE;
    CK_OBJECT_HANDLE    hObject = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;

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

    QString strP = mPText->text();
    BIN binP = {0,0};

    if( !strP.isEmpty() )
    {
        JS_BIN_decodeHex( strP.toStdString().c_str(), &binP );
        sTemplate[uCount].type = CKA_PRIME;
        sTemplate[uCount].pValue = binP.pVal;
        sTemplate[uCount].ulValueLen = binP.nLen;
        uCount++;
    }

    QString strQ = mQText->text();
    BIN binQ = {0,0};

    if( !strQ.isEmpty() )
    {
        JS_BIN_decodeHex( strQ.toStdString().c_str(), &binQ );
        sTemplate[uCount].type = CKA_SUBPRIME;
        sTemplate[uCount].pValue = binQ.pVal;
        sTemplate[uCount].ulValueLen = binQ.nLen;
        uCount++;
    }

    QString strG = mGText->text();
    BIN binG = {0,0};

    if( !strG.isEmpty() )
    {
        JS_BIN_decodeHex( strG.toStdString().c_str(), &binG );
        sTemplate[uCount].type = CKA_BASE;
        sTemplate[uCount].pValue = binG.pVal;
        sTemplate[uCount].ulValueLen = binG.nLen;
        uCount++;
    }

    QString strPublic = mPublicText->text();
    BIN binPublic = {0,0};

    if( !strPublic.isEmpty() )
    {
        JS_BIN_decodeHex( strPublic.toStdString().c_str(), &binPublic );
        sTemplate[uCount].type = CKA_VALUE;
        sTemplate[uCount].pValue = binPublic.pVal;
        sTemplate[uCount].ulValueLen = binPublic.nLen;
        uCount++;
    }


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

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binPublic );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "fail to create DSA public key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("success to create DSA public key[H:%1]").arg( hObject ), this );
    manApplet->showTypeList( index, HM_ITEM_TYPE_PUBLICKEY );

    QDialog::accept();
}

void CreateDSAPubKeyDlg::clickGenKey()
{
    int ret = 0;
    BIN binPub = {0,0};
    BIN binPri = {0,0};
    JDSAKeyVal sDSAKey;

    int nKeyLen = mParamCombo->currentText().toInt();

    memset( &sDSAKey, 0x00, sizeof(sDSAKey));

    ret = JS_PKI_DSA_GenKeyPair( nKeyLen, &binPub, &binPri );
    if( ret != 0 ) goto end;

    ret = JS_PKI_getDSAKeyVal( &binPri, &sDSAKey );
    if( ret != 0 ) goto end;

    mGText->setText( sDSAKey.pG );
    mPText->setText( sDSAKey.pP );
    mQText->setText( sDSAKey.pQ );
    mPublicText->setText( sDSAKey.pPublic );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_PKI_resetDSAKeyVal( &sDSAKey );
}

void CreateDSAPubKeyDlg::clickUseSKI()
{
    bool bVal = mUseSKICheck->isChecked();
    mIDText->setEnabled( !bVal );
}

void CreateDSAPubKeyDlg::clickFindKey()
{
    int ret = 0;
    int nKeyType = -1;
    BIN binKey = {0,0};
    JDSAKeyVal sDSAKey;

    QString strPath = manApplet->curFile();
    QString fileName = findFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.length() < 1 ) return;

    memset( &sDSAKey, 0x00, sizeof(sDSAKey));

    ret = JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binKey );
    if( ret < 0 )
    {
        manApplet->elog( QString( "fail to read key:%1").arg( ret) );
        goto end;
    }

    nKeyType = JS_PKI_getPriKeyType( &binKey );
    if( nKeyType < 0 )
    {
        nKeyType = JS_PKI_getPubKeyType( &binKey );
        if( nKeyType != JS_PKI_KEY_TYPE_DSA )
        {
            manApplet->elog( QString( "invalid public key type: %1").arg( nKeyType ));
            goto end;
        }

        ret = JS_PKI_getDSAKeyValFromPub( &binKey, &sDSAKey );
        if( ret != 0 ) goto end;
    }
    else if( nKeyType != JS_PKI_KEY_TYPE_DSA )
    {
        manApplet->elog( QString( "invalid private key type: %1").arg( nKeyType ));
        goto end;
    }
    else
    {
        ret = JS_PKI_getDSAKeyVal( &binKey, &sDSAKey );
        if( ret != 0 ) goto end;
    }

    mGText->setText( sDSAKey.pG );
    mPText->setText( sDSAKey.pP );
    mQText->setText( sDSAKey.pQ );
    mPublicText->setText( sDSAKey.pPublic );

    manApplet->setCurFile( fileName );
    ret = 0;

end :
    if( ret != 0 ) manApplet->warningBox( tr( "fail to get valid key:%1").arg(ret), this );

    JS_BIN_reset( &binKey );
    JS_PKI_resetDSAKeyVal( &sDSAKey );
}

void CreateDSAPubKeyDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void CreateDSAPubKeyDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void CreateDSAPubKeyDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void CreateDSAPubKeyDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}

void CreateDSAPubKeyDlg::clickVerifyRecover()
{
    mVerifyRecoverCombo->setEnabled(mVerifyRecoverCheck->isChecked());
}

void CreateDSAPubKeyDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void CreateDSAPubKeyDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void CreateDSAPubKeyDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void CreateDSAPubKeyDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}


void CreateDSAPubKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void CreateDSAPubKeyDlg::clickTrusted()
{
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
}

void CreateDSAPubKeyDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void CreateDSAPubKeyDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void CreateDSAPubKeyDlg::changeP( const QString& text )
{
    int nLen = getDataLen( DATA_HEX, text );
    mPLenText->setText( QString("%1").arg(nLen));
}

void CreateDSAPubKeyDlg::changeQ( const QString& text )
{
    int nLen = getDataLen( DATA_HEX, text );
    mQLenText->setText( QString("%1").arg(nLen));
}

void CreateDSAPubKeyDlg::changeG( const QString& text )
{
    int nLen = getDataLen( DATA_HEX, text );
    mGLenText->setText( QString("%1").arg(nLen));
}

void CreateDSAPubKeyDlg::changePublic( const QString& text )
{
    int nLen = getDataLen( DATA_HEX, text );
    mPublicLenText->setText( QString("%1").arg(nLen));
}

void CreateDSAPubKeyDlg::setDefaults()
{
    mParamCombo->setCurrentText( "2048" );

    mLabelText->setText( "DSA Public Key Label" );
    mIDText->setText( "01020304" );

    mUseSKICheck->setChecked(true);
    clickUseSKI();

    /*
    mEncryptCheck->setChecked(true);
    mEncryptCombo->setEnabled(true);
    mEncryptCombo->setCurrentIndex(1);


    mTokenCheck->setChecked(true);
    mTokenCombo->setEnabled(true);
    mTokenCombo->setCurrentIndex(1);

    mVerifyCheck->setChecked(true);
    mVerifyCombo->setEnabled(true);
    mVerifyCombo->setCurrentIndex(1);
    */

    QDateTime nowTime;
    nowTime.setSecsSinceEpoch( time(NULL) );

    mStartDateEdit->setDate( nowTime.date() );
    mEndDateEdit->setDate( nowTime.date() );
}

int CreateDSAPubKeyDlg::getSKI( BIN *pSKI )
{
    int ret = 0;
    JDSAKeyVal  sDSAKey;
    BIN binPub = {0,0};

    memset( &sDSAKey, 0x00, sizeof(sDSAKey));

    JS_PKI_setDSAKeyVal( &sDSAKey,
                         mGText->text().toStdString().c_str(),
                         mPText->text().toStdString().c_str(),
                         mQText->text().toStdString().c_str(),
                         mPublicText->text().toStdString().c_str(),
                         NULL );

    ret = JS_PKI_encodeDSAPublicKey( &sDSAKey, &binPub );
    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to encode private key: %d").arg(ret));
        goto end;
    }

    ret = JS_PKI_getKeyIdentifier( &binPub, pSKI );
    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to get key identifier: %1").arg(ret));
        goto end;
    }

end :
    JS_PKI_resetDSAKeyVal( &sDSAKey );
    JS_BIN_reset( &binPub );
    return ret;
}
