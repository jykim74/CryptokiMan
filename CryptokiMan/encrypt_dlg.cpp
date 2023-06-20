#include "encrypt_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"

static CK_BBOOL kTrue = CK_TRUE;
static CK_BBOOL kFalse = CK_FALSE;

static QStringList sMechList = {
    "CKM_DES3_ECB", "CKM_DES3_CBC", "CKM_AES_ECB", "CKM_AES_CBC",
};

static QStringList sPublicMechList = {
    "CKM_RSA_PKCS"
};

static QStringList sInputList = { "String", "Hex", "Base64" };

static QStringList sKeyList = { "SECRET", "PUBLIC" };

EncryptDlg::EncryptDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    session_ = -1;

    setupUi(this);
    initUI();
}

EncryptDlg::~EncryptDlg()
{

}

void EncryptDlg::initUI()
{
    mKeyTypeCombo->addItems(sKeyList);
    mMechCombo->addItems( sMechList );
    mInputCombo->addItems( sInputList );

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mEncryptBtn, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged(const QString&)), this, SLOT(outputChanged()));


    initialize();
    keyTypeChanged(0);
}

void EncryptDlg::slotChanged(int index)
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

void EncryptDlg::setSelectedSlot(int index)
{
    slotChanged(index);

    keyTypeChanged( 0 );
}

void EncryptDlg::setObject( int type, long hObj )
{
    BIN binVal = {0,0};
    char *pLabel = NULL;

    if( type == OBJ_SECRET_IDX )
    {
        mKeyTypeCombo->setCurrentText( sKeyList[0] );
    }
    else if( type == OBJ_PUBKEY_IDX )
    {
        mKeyTypeCombo->setCurrentText( sKeyList[1] );
    }

    manApplet->cryptokiAPI()->GetAttributeValue2( session_, hObj, CKA_LABEL, &binVal );
    JS_BIN_string( &binVal, &pLabel );
    JS_BIN_reset( &binVal );

    mLabelCombo->setCurrentText( pLabel );
    mObjectText->setText( QString("%1").arg( hObj ));

    if( pLabel ) JS_free( pLabel );
}

void EncryptDlg::changeType( int type )
{
    if( type == OBJ_SECRET_IDX )
        mKeyTypeCombo->setCurrentIndex(0);
    else
        mKeyTypeCombo->setCurrentIndex(1);
}

void EncryptDlg::initialize()
{

}

void EncryptDlg::keyTypeChanged( int index )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[1];
    CK_ULONG uCnt = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;
    mMechCombo->clear();

    if( mKeyTypeCombo->currentText() == sKeyList[0] )
    {
        objClass = CKO_SECRET_KEY;
        mMechCombo->addItems(sMechList);
    }
    else if( mKeyTypeCombo->currentText() == sKeyList[1] )
    {
        objClass = CKO_PUBLIC_KEY;
        mMechCombo->addItems(sPublicMechList);
    }

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_ENCRYPT;
    sTemplate[uCnt].pValue = &kTrue;
    sTemplate[uCnt].ulValueLen = sizeof(CK_BBOOL);
    uCnt++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal(session_);
    if( rv != CKR_OK ) return;

    mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char    *pStr = NULL;
        BIN binLabel = {0,0};

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

        QVariant objVal = QVariant((int)sObjects[i]);
        JS_BIN_string( &binLabel, &pStr );
        mLabelCombo->addItem( pStr, objVal );
        if( pStr ) JS_free( pStr );
        JS_BIN_reset(&binLabel);
    }

    if( uObjCnt > 0 )
    {
        QString strHandle = QString("%1").arg( sObjects[0] );
        mObjectText->setText( strHandle );
    }
}

void EncryptDlg::labelChanged( int index )
{
    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}

void EncryptDlg::inputChanged()
{
    QString strInput = mInputText->toPlainText();
    int nLen = getDataLen( mInputCombo->currentText(), strInput );
    mInputLenText->setText( QString("%1").arg( nLen ));
}

void EncryptDlg::outputChanged()
{
    QString strOutput = mOutputText->toPlainText();
    int nLen = getDataLen( DATA_HEX, strOutput );
    mOutputLenText->setText( QString("%1").arg(nLen));
}

void EncryptDlg::clickInit()
{
    int rv = -1;

    CK_MECHANISM sMech;
    BIN binParam = {0,0};

    long hObject = mObjectText->text().toLong();

    sMech.mechanism = JS_PKCS11_GetCKMType( mMechCombo->currentText().toStdString().c_str());
    QString strParam = mParamText->text();

    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );
        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }

    rv = manApplet->cryptokiAPI()->EncryptInit( session_, &sMech, hObject );

    if( rv != CKR_OK )
    {
        mStatusLabel->setText("");
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("fail to run EncryptInit(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    mStatusLabel->setText( "Init" );
    mOutputText->setPlainText( "" );
}

void EncryptDlg::clickUpdate()
{
    int rv = -1;

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert data."), this );
        mInputText->setFocus();
        return;
    }

    BIN binInput = {0,0};

    if( mInputCombo->currentIndex() == 0 )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length());
    else if( mInputCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    unsigned char *pEncPart = NULL;
    long uEncPartLen = binInput.nLen + 64;

    pEncPart = (unsigned char *)JS_malloc( binInput.nLen + 64 );
    if( pEncPart == NULL ) return;

    rv = manApplet->cryptokiAPI()->EncryptUpdate( session_, binInput.pVal, binInput.nLen, pEncPart, (CK_ULONG_PTR)&uEncPartLen );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText("");
        if( pEncPart ) JS_free( pEncPart );
        manApplet->warningBox( tr("fail to run EncryptUpdate(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    BIN binPart = {0,0};
    char *pHex = NULL;
    JS_BIN_set( &binPart, pEncPart, uEncPartLen );
    JS_BIN_encodeHex( &binPart, &pHex );

    QString strRes = mStatusLabel->text();
    QString strOutput = mOutputText->toPlainText();

    strRes += "|Update";
    strOutput += pHex;

    mStatusLabel->setText( strRes );
    mOutputText->setPlainText( strOutput );

    if( pEncPart ) JS_free( pEncPart );
    if( pHex ) JS_free( pHex );
}

void EncryptDlg::clickFinal()
{
    int rv = -1;

    unsigned char *pEncPart = NULL;
    long uEncPartLen = 0;

    pEncPart = (unsigned char *)JS_malloc( mInputText->toPlainText().length() / 2 + 64 );
    if( pEncPart == NULL ) return;

    BIN binEncPart = {0,0};
    char *pHex = NULL;

    rv = manApplet->cryptokiAPI()->EncryptFinal( session_, pEncPart, (CK_ULONG_PTR)&uEncPartLen );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText( "" );
        if( pEncPart ) JS_free( pEncPart );
        manApplet->warningBox( tr("fail to run EncryptFinal(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }


    JS_BIN_set( &binEncPart, pEncPart, uEncPartLen );
    JS_BIN_encodeHex( &binEncPart, &pHex );

    QString strRes = mStatusLabel->text();
    strRes += "|Final";
    QString strOutput = mOutputText->toPlainText();
    strOutput += pHex;

    mOutputText->setPlainText( strOutput );
    mStatusLabel->setText( strRes );
    if( pEncPart ) JS_free( pEncPart );
    if( pHex ) JS_free(pHex);
    JS_BIN_reset( &binEncPart );
}

void EncryptDlg::clickEncrypt()
{
    int rv = -1;

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr( "You have to insert data."), this );
        mInputText->setFocus();
        return;
    }

    BIN binInput = {0,0};

    if( mInputCombo->currentIndex() == 0 )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length());
    else if( mInputCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    unsigned char *pEncData = NULL;
    long uEncDataLen = binInput.nLen + 64;
    BIN binEncData = {0,0};

    pEncData = (unsigned char *)JS_malloc( binInput.nLen + 64 );
    if( pEncData == NULL ) return;

    rv = manApplet->cryptokiAPI()->Encrypt( session_, binInput.pVal, binInput.nLen, pEncData, (CK_ULONG_PTR)&uEncDataLen );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText( "" );
        if( pEncData ) JS_free( pEncData );
        manApplet->warningBox( tr("fail to run Encrypt(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    char *pHex = NULL;
    JS_BIN_set( &binEncData, pEncData, uEncDataLen );
    JS_BIN_encodeHex( &binEncData, &pHex );
    mOutputText->setPlainText( pHex );
    QString strRes = mStatusLabel->text();
    strRes += "|Encrypt";
    mStatusLabel->setText( strRes );

    if( pEncData ) JS_free( pEncData );
    if( pHex ) JS_free(pHex);
    JS_BIN_reset( &binEncData );
}

void EncryptDlg::clickClose()
{
    this->hide();
}
