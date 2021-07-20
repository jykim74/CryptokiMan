#include "sign_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"

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

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT( slotChanged(int) ));
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

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void SignDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void SignDlg::initialize()
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

void SignDlg::keyTypeChanged( int index )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[1];
    CK_ULONG uCnt = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;

    mMechCombo->clear();

    if( index == 0 )
    {
        objClass = CKO_PRIVATE_KEY;
        mMechCombo->addItems( sMechList );
    }
    else if( index == 1 )
    {
        objClass = CKO_SECRET_KEY;
        mMechCombo->addItems( sSecretMechList );
    }


    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( hSession, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
    if( rv != CKR_OK ) return;

    mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char    *pStr = NULL;
        BIN binLabel = {0,0};

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, sObjects[i], CKA_LABEL, &binLabel );

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
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

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
    rv = manApplet->cryptokiAPI()->SignInit( hSession, &sMech, uObject );

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
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

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

    rv = manApplet->cryptokiAPI()->SignUpdate( hSession, binInput.pVal, binInput.nLen );

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
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    unsigned char sSign[1024];
    long uSignLen = 1024;

    rv = manApplet->cryptokiAPI()->SignFinal( hSession, sSign, (CK_ULONG_PTR)&uSignLen );

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
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();


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

    rv = manApplet->cryptokiAPI()->Sign( hSession, binInput.pVal, binInput.nLen, sSign, (CK_ULONG_PTR)&uSignLen );

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