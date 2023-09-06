#include "create_ec_pub_key_dlg.h"
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

CreateECPubKeyDlg::CreateECPubKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    connect( mECPointsText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECPoints(const QString&)));
    connect( mECParamsText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECParams(const QString&)));

    initialize();
    setDefaults();

    tabWidget->setCurrentIndex(0);
}

CreateECPubKeyDlg::~CreateECPubKeyDlg()
{

}

void CreateECPubKeyDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void CreateECPubKeyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}


void CreateECPubKeyDlg::initialize()
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

void CreateECPubKeyDlg::initAttributes()
{
    mPrivateCombo->addItems(sFalseTrue);
    mEncryptCombo->addItems(sFalseTrue);
    mWrapCombo->addItems(sFalseTrue);
    mVerifyCombo->addItems(sFalseTrue);
    mVerifyRecoverCombo->addItems(sFalseTrue);
    mDeriveCombo->addItems(sFalseTrue);
    mModifiableCombo->addItems(sFalseTrue);
    mTokenCombo->addItems(sFalseTrue);

    QDate nowDate = QDate::currentDate();
    mStartDateEdit->setDate(nowDate);
    mEndDateEdit->setDate(nowDate);
}

void CreateECPubKeyDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
    mVerifyRecoverCombo->setEnabled(mVerifyRecoverCheck->isChecked());
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void CreateECPubKeyDlg::connectAttributes()
{
    connect( mUseSKICheck, SIGNAL(clicked()), this, SLOT(clickUseSKI()));

    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mEncryptCheck, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mWrapCheck, SIGNAL(clicked()), this, SLOT(clickWrap()));
    connect( mVerifyCheck, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mVerifyRecoverCheck, SIGNAL(clicked()), this, SLOT(clickVerifyRecover()));
    connect( mDeriveCheck, SIGNAL(clicked()), this, SLOT(clickDerive()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mStartDateCheck, SIGNAL(clicked()), this, SLOT(clickStartDate()));
    connect( mEndDateCheck, SIGNAL(clicked()), this, SLOT(clickEndDate()));
}

void CreateECPubKeyDlg::accept()
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
    CK_KEY_TYPE keyType = CKK_EC;

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

    QString strECPoints = mECPointsText->text();
    BIN binECPoints = {0,0};

    if( !strECPoints.isEmpty() )
    {
        JS_BIN_decodeHex( strECPoints.toStdString().c_str(), &binECPoints );
        sTemplate[uCount].type = CKA_EC_POINT;
        sTemplate[uCount].pValue = binECPoints.pVal;
        sTemplate[uCount].ulValueLen = binECPoints.nLen;
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

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binECParams );
    JS_BIN_reset( &binECPoints );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "fail to create EC public key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("success to create EC public key"), this );
    manApplet->showTypeList( index, HM_ITEM_TYPE_PUBLICKEY );

    QDialog::accept();
}

void CreateECPubKeyDlg::clickUseSKI()
{
    bool bVal = mUseSKICheck->isChecked();
    mIDText->setEnabled( !bVal );
}


void CreateECPubKeyDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void CreateECPubKeyDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void CreateECPubKeyDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void CreateECPubKeyDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}

void CreateECPubKeyDlg::clickVerifyRecover()
{
    mVerifyRecoverCombo->setEnabled(mVerifyRecoverCheck->isChecked());
}

void CreateECPubKeyDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void CreateECPubKeyDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void CreateECPubKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}


void CreateECPubKeyDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void CreateECPubKeyDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}

void CreateECPubKeyDlg::changeECPoints( const QString& text )
{
    int nLen = getDataLen( DATA_HEX, text );
    mECPointsLenText->setText( QString("%1").arg(nLen));
}

void CreateECPubKeyDlg::changeECParams( const QString& text )
{
    int nLen = getDataLen( DATA_HEX, text );
    mECParamsLenText->setText( QString("%1").arg(nLen));
}

void CreateECPubKeyDlg::setDefaults()
{
    mLabelText->setText( "EC Public Key Label" );
    mIDText->setText( "01020304" );

    mUseSKICheck->setChecked(true);
    clickUseSKI();

    mEncryptCheck->setChecked(true);
    mEncryptCombo->setEnabled(true);
    mEncryptCombo->setCurrentIndex(1);


    mTokenCheck->setChecked(true);
    mTokenCombo->setEnabled(true);
    mTokenCombo->setCurrentIndex(1);

    mVerifyCheck->setChecked(true);
    mVerifyCombo->setEnabled(true);
    mVerifyCombo->setCurrentIndex(1);

    QDateTime nowTime;
    nowTime.setTime_t( time(NULL) );

    mStartDateEdit->setDate( nowTime.date() );
    mEndDateEdit->setDate( nowTime.date() );
}

int CreateECPubKeyDlg::getSKI( BIN *pSKI )
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
    QString strParam = mECParamsText->text();
    QString strPoints = mECPointsText->text();

    memset( &sECKey, 0x00, sizeof(sECKey));
    memset(sOID, 0x00, sizeof(sOID));

    JS_BIN_decodeHex( strPoints.toStdString().c_str(), &binPoints );
    JS_BIN_decodeHex( strParam.toStdString().c_str(), &binOID );

    ret = JS_PKI_getStringFromOID( &binOID, sOID );
    if( ret != 0 )
    {
        manApplet->elog( QString( "invalid parameters: %1").arg(ret));
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
