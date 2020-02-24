#include "verify_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

static QStringList sMechList = {
    "CKM_SHA1_RSA_PKCS", "CKM_SHA256_RSA_PKCS", "CKM_SHA384_RSA_PKCS",
    "CKM_SHA512_RSA_PKCS"
};

static QStringList sSecretMechList = {
    "CKM_SHA_1_HMAC", "CKM_SHA256_HMAC", "CKM_SHA384_HMAC", "CKM_SHA512_HMAC"
};


static QStringList sInputList = { "String", "Hex", "Base64" };

static QStringList sKeyList = { "PUBLIC", "SECRET" };


VerifyDlg::VerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
}

VerifyDlg::~VerifyDlg()
{

}

void VerifyDlg::initUI()
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
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));

    initialize();
    keyTypeChanged(0);
}

void VerifyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void VerifyDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void VerifyDlg::initialize()
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

void VerifyDlg::keyTypeChanged( int index )
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[1];
    CK_ULONG uCnt = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;

    mMechCombo->clear();

    if( index == 0 )
    {
        objClass = CKO_PUBLIC_KEY;
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

    JS_PKCS11_FindObjectsInit( p11_ctx, hSession, sTemplate, uCnt );
    JS_PKCS11_FindObjects( p11_ctx, hSession, sObjects, uMaxObjCnt, &uObjCnt );
    JS_PKCS11_FindObjectsFinal( p11_ctx, hSession );

    mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char    *pStr = NULL;
        BIN binLabel = {0,0};
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, sObjects[i], CKA_LABEL, &binLabel );
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

void VerifyDlg::labelChanged( int index )
{
    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}

void VerifyDlg::clickInit()
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

    CK_MECHANISM sMech;
    BIN binParam = {0,0};
    long uObject = mObjectText->text().toLong();

    sMech.mechanism = JS_PKCS11_GetCKMType( mMechCombo->currentText().toStdString().c_str());
    QString strParam = mParamText->text();

    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );
        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }

    rv = JS_PKCS11_VerifyInit( p11_ctx, hSession, &sMech, uObject );
    if( rv != CKR_OK )
    {
        mStatusLabel->setText("");
        manApplet->warningBox( tr("fail to run VerifyInit(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    mStatusLabel->setText( "Init" );
}

void VerifyDlg::clickUpdate()
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

    QString strInput = mInputText->text();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert data."), this );
        return;
    }

    BIN binInput = {0,0};

    if( mInputCombo->currentIndex() == 0 )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );


    rv = JS_PKCS11_VerifyUpdate(p11_ctx, hSession, binInput.pVal, binInput.nLen );
    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to run VerifyUpdate(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    QString strRes = mStatusLabel->text();

    strRes += "|Update";
    mStatusLabel->setText( strRes );
}

void VerifyDlg::clickFinal()
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

    QString strSign = mSignText->toPlainText();

    if( strSign.isEmpty() )
    {
        manApplet->warningBox( tr( "You have to insert signature."), this );
        return;
    }

    BIN binSign = {0,0};
    JS_BIN_decodeHex( strSign.toStdString().c_str(), &binSign );

    rv = JS_PKCS11_VerifyFinal( p11_ctx, hSession, binSign.pVal, binSign.nLen );
    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("Signature is bad(%1).").arg(JS_PKCS11_GetErrorMsg(rv)), this );
    }
    else
    {
        manApplet->messageBox( tr("Signature is good."), this );
    }

    QString strRes = mStatusLabel->text();
    strRes += "|Final";
    mStatusLabel->setText( strRes );
}

void VerifyDlg::clickVerify()
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

    QString strInput = mInputText->text();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert data."), this );
        return;
    }

    QString strSign = mSignText->toPlainText();
    if( strSign.isEmpty() )
    {
        manApplet->warningBox(tr( "You have to insert signature." ), this );
        return;
    }

    BIN binInput = {0,0};

    if( mInputCombo->currentIndex() == 0 )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    BIN binSign = {0,0};
    JS_BIN_decodeHex( strSign.toStdString().c_str(), &binSign );


    rv = JS_PKCS11_Verify( p11_ctx, hSession, binInput.pVal, binInput.nLen, binSign.pVal, binSign.nLen );
    if( rv != CKR_OK )
        manApplet->warningBox( tr( "Signature is bad(%1)." ).arg(JS_PKCS11_GetErrorMsg(rv)), this );
    else
        manApplet->messageBox( tr( "Signature is good." ), this );

    QString strRes = mStatusLabel->text();
    strRes += "|Verify";

    mStatusLabel->setText(strRes);
}

void VerifyDlg::clickClose()
{
    this->hide();
}
