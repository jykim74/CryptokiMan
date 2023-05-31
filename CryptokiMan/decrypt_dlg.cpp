#include "decrypt_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"

static QStringList sMechList = {
    "CKM_DES3_ECB", "CKM_DES3_CBC", "CKM_AES_ECB", "CKM_AES_CBC"
};

static QStringList sPrivateMechList = {
    "CKM_RSA_PKCS"
};

static QStringList sInputList = { "Hex", "Base64" };

static QStringList sKeyList = { "SECRET", "PRIVATE" };

static CK_BBOOL kTrue = CK_TRUE;
static CK_BBOOL kFalse = CK_FALSE;

DecryptDlg::DecryptDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    session_ = -1;

    setupUi(this);
    initUI();
}

DecryptDlg::~DecryptDlg()
{

}

void DecryptDlg::initUI()
{
    mKeyTypeCombo->addItems(sKeyList);
    mMechCombo->addItems( sMechList );
    mInputCombo->addItems( sInputList );

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mDecryptBtn, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));

    initialize();
    keyTypeChanged(0);
}

void DecryptDlg::slotChanged(int index)
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

void DecryptDlg::setSelectedSlot(int index)
{
    slotChanged(index);

    keyTypeChanged( 0 );
}

void DecryptDlg::setObject( int type, long hObj )
{
    BIN binVal = {0,0};
    char *pLabel = NULL;

    if( type == OBJ_SECRET_IDX )
    {
        mKeyTypeCombo->setCurrentText( sKeyList[0] );
    }
    else if( type == OBJ_PRIKEY_IDX )
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

void DecryptDlg::changeType( int type )
{
    if( type == OBJ_SECRET_IDX )
        mKeyTypeCombo->setCurrentIndex(0);
    else
        mKeyTypeCombo->setCurrentIndex(1);
}

void DecryptDlg::initialize()
{

}

void DecryptDlg::keyTypeChanged( int index )
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
        objClass = CKO_PRIVATE_KEY;
        mMechCombo->addItems(sPrivateMechList);
    }

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_DECRYPT;
    sTemplate[uCnt].pValue = &kTrue;
    sTemplate[uCnt].ulValueLen = sizeof(CK_BBOOL);
    uCnt++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
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

void DecryptDlg::labelChanged( int index )
{
    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}


void DecryptDlg::clickInit()
{
    int rv = -1;

    long hObject = mObjectText->text().toLong();

    CK_MECHANISM sMech;
    BIN binParam = {0,0};

    sMech.mechanism = JS_PKCS11_GetCKMType( mMechCombo->currentText().toStdString().c_str());

    QString strParam = mParamText->text();

    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );
        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }

    rv = manApplet->cryptokiAPI()->DecryptInit( session_, &sMech, hObject );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText("");
        mStatusLabel->setText("");
        manApplet->warningBox( tr("fail to run DecryptInit(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    mOutputText->setPlainText("");
    mStatusLabel->setText( "Init" );
}

void DecryptDlg::clickUpdate()
{
    int rv = -1;

    QString strInput = mInputText->text();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert data."), this );
        mInputText->setFocus();
        return;
    }

    BIN binInput = {0,0};

    if( mInputCombo->currentText() == "Hex" )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputCombo->currentText() == "Base64" )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );


    unsigned char *pDecPart = NULL;
    long uDecPartLen = binInput.nLen;

    pDecPart = (unsigned char *)JS_malloc( binInput.nLen );
    if( pDecPart == NULL ) return;

    BIN binDecPart = {0,0};

    rv = manApplet->cryptokiAPI()->DecryptUpdate( session_, binInput.pVal, binInput.nLen, pDecPart, (CK_ULONG_PTR)&uDecPartLen );

    if( rv != CKR_OK )
    {
        if( pDecPart ) JS_free( pDecPart );
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("fail to run DecryptUpdate(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        return;
    }

    char *pHex = NULL;
    JS_BIN_set( &binDecPart, pDecPart, uDecPartLen );
    JS_BIN_encodeHex( &binDecPart, &pHex );
    QString strDec = mOutputText->toPlainText();
    strDec += pHex;
    mOutputText->setPlainText( strDec );
    if( pHex ) JS_free(pHex);
    JS_BIN_reset( &binDecPart );

    QString strRes = mStatusLabel->text();
    strRes += "|Update";
    mStatusLabel->setText( strRes );
    if( pDecPart ) JS_free( pDecPart );
}

void DecryptDlg::clickFinal()
{
    int rv = -1;

    unsigned char *pDecPart = NULL;
    long uDecPartLen = mInputText->text().length();

    BIN binDecPart = {0,0};

    pDecPart = (unsigned char *)JS_malloc( mInputText->text().length() );
    if( pDecPart == NULL )return;

    rv = manApplet->cryptokiAPI()->DecryptFinal( session_, pDecPart, (CK_ULONG_PTR)&uDecPartLen );

    if( rv != CKR_OK )
    {
        if( pDecPart ) JS_free( pDecPart );
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("fail to run DecryptFinal(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    QString strRes = mStatusLabel->text();
    QString strDec = mOutputText->toPlainText();
    char *pHex = NULL;

    JS_BIN_set( &binDecPart, pDecPart, uDecPartLen );
    JS_BIN_encodeHex( &binDecPart, &pHex );

    strRes += "|Final";
    strDec += pHex;

    mStatusLabel->setText( strRes );
    mOutputText->setPlainText( strDec );

    if( pDecPart ) JS_free( pDecPart );
    if( pHex ) JS_free( pHex );
    JS_BIN_reset( &binDecPart );
}

void DecryptDlg::clickDecrypt()
{
    int rv = -1;

    QString strInput = mInputText->text();
    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert data"), this );
        mInputText->setFocus();
        return;
    }

    BIN binInput = {0,0};

    if( mInputCombo->currentText() == "Hex" )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputCombo->currentText() == "Base64" )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    unsigned char *pDecData = NULL;
    long uDecDataLen = mInputText->text().length();
    pDecData = (unsigned char *)JS_malloc( mInputText->text().length() );

    rv = manApplet->cryptokiAPI()->Decrypt( session_, binInput.pVal, binInput.nLen, pDecData, (CK_ULONG_PTR)&uDecDataLen );

    if( rv != CKR_OK )
    {
        if( pDecData ) JS_free( pDecData );
        mOutputText->setPlainText( "" );
        manApplet->warningBox( tr("fail to run Decrypt(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    QString strRes = mStatusLabel->text();
    strRes += "|Decrypt";
    mStatusLabel->setText( strRes );

    BIN binDecData = {0,0};
    char *pHex = NULL;
    JS_BIN_set( &binDecData, pDecData, uDecDataLen );
    JS_BIN_encodeHex( &binDecData, &pHex );

    mOutputText->setPlainText( pHex );
    if( pDecData ) JS_free( pDecData );
    if( pHex ) JS_free(pHex);
    JS_BIN_reset( &binDecData );
}

void DecryptDlg::clickClose()
{
    this->hide();
}
