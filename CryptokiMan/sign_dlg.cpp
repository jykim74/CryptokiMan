#include "sign_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"

static CK_BBOOL kTrue = CK_TRUE;
static CK_BBOOL kFalse = CK_FALSE;

static QStringList sMechList = {
    "CKM_RSA_PKCS", "CKM_SHA1_RSA_PKCS", "CKM_SHA256_RSA_PKCS", "CKM_SHA384_RSA_PKCS", "CKM_SHA512_RSA_PKCS",
    "CKM_ECDSA", "CKM_ECDSA_SHA1", "CKM_ECDSA_SHA256", "CKM_ECDSA_SHA384", "CKM_ECDSA_SHA512"
};

static QStringList sSecretMechList = {
    "CKM_SHA_1_HMAC", "CKM_SHA256_HMAC", "CKM_SHA384_HMAC", "CKM_SHA512_HMAC"
};

static QStringList sInputList = { "String", "Hex", "Base64" };

static QStringList sKeyList = { "PRIVATE", "SECRET" };

SignDlg::SignDlg(QWidget *parent) :
    QDialog(parent)
{
    session_ = -1;
    slot_index_ = -1;

    setupUi(this);

    initUI();
}

SignDlg::~SignDlg()
{

}

void SignDlg::initUI()
{
    mKeyTypeCombo->addItems(sKeyList);
    mMechCombo->addItems( sMechList );
    mInputCombo->addItems( sInputList );

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mSignBtn, SIGNAL(clicked()), this, SLOT(clickSign()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));

    initialize();
    keyTypeChanged(0);
}

void SignDlg::slotChanged(int index)
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

void SignDlg::setSelectedSlot(int index)
{
    slotChanged( index );

    keyTypeChanged( 0 );
}

void SignDlg::changeType( int type )
{
    if( type == OBJ_SECRET_IDX )
        mKeyTypeCombo->setCurrentIndex(1);
    else
        mKeyTypeCombo->setCurrentIndex(0);
}

void SignDlg::setObject( int type, long hObj )
{
    BIN binVal = {0,0};
    char *pLabel = NULL;

    if( type == OBJ_PRIKEY_IDX )
    {
        mKeyTypeCombo->setCurrentText( sKeyList[0] );
    }
    else if( type == OBJ_SECRET_IDX )
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

void SignDlg::initialize()
{

}

void SignDlg::keyTypeChanged( int index )
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
        objClass = CKO_PRIVATE_KEY;
        mMechCombo->addItems( sMechList );
    }
    else if( mKeyTypeCombo->currentText() == sKeyList[1] )
    {
        objClass = CKO_SECRET_KEY;
        mMechCombo->addItems( sSecretMechList );
    }

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_SIGN;
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

void SignDlg::labelChanged( int index )
{
    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}

void SignDlg::clickInit()
{
    int rv = -1;

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

    CK_OBJECT_HANDLE uObject = mObjectText->text().toLong();
    rv = manApplet->cryptokiAPI()->SignInit( session_, &sMech, uObject );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText( "" );
        mStatusLabel->setText( "" );
        manApplet->warningBox( tr("fail to run SignInit(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
    }
    else
    {
        mOutputText->setPlainText( "" );
        mStatusLabel->setText( "Init" );
    }
}

void SignDlg::clickUpdate()
{
    int rv = -1;

    QString strInput = mInputText->text();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox(tr( "You have to insert data."), this );
        return;
    }

    BIN binInput = {0,0};

    if( mInputCombo->currentIndex() == 0 )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    rv = manApplet->cryptokiAPI()->SignUpdate( session_, binInput.pVal, binInput.nLen );

    if( rv != CKR_OK )
    {
        manApplet->warningBox(tr("fail to run SignUpdate(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    QString strRes = mStatusLabel->text();
    strRes += "|Update";

    mStatusLabel->setText( strRes );
}

void SignDlg::clickFinal()
{
    int rv = -1;

    unsigned char sSign[1024];
    long uSignLen = 1024;

    rv = manApplet->cryptokiAPI()->SignFinal( session_, sSign, (CK_ULONG_PTR)&uSignLen );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to run SignFinal(%1)").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        mOutputText->setPlainText("");
        return;
    }

    char *pHex = NULL;
    BIN binSign = {0,0};
    JS_BIN_set( &binSign, sSign, uSignLen );
    JS_BIN_encodeHex( &binSign, &pHex );

    mOutputText->setPlainText( pHex );
    QString strRes = mStatusLabel->text();
    strRes += "|Final";
    mStatusLabel->setText( strRes );

    if( pHex ) JS_free(pHex);
    JS_BIN_reset(&binSign);
}

void SignDlg::clickSign()
{
    int rv = -1;

    QString strInput = mInputText->text();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert data."), this );
        return;
    }

    BIN binInput = {0,0};

    if( mInputCombo->currentIndex() == 0 )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length());
    else if( mInputCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    unsigned char sSign[1024];
    long uSignLen = 1024;

    rv = manApplet->cryptokiAPI()->Sign( session_, binInput.pVal, binInput.nLen, sSign, (CK_ULONG_PTR)&uSignLen );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("fail to run Sign(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    char *pHex = NULL;
    BIN binSign = {0,0};
    JS_BIN_set( &binSign, sSign, uSignLen);
    JS_BIN_encodeHex( &binSign, &pHex );
    mOutputText->setPlainText( pHex );

    QString strRes = mStatusLabel->text();
    strRes += "|Sign";
    mStatusLabel->setText( strRes );

    if( pHex ) JS_free(pHex);
    JS_BIN_reset(&binSign);
}

void SignDlg::clickClose()
{
    this->hide();
}
