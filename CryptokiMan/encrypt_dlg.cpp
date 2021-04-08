#include "encrypt_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

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

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT( slotChanged(int) ));
    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mEncryptBtn, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));

    initialize();
    keyTypeChanged(0);
}

void EncryptDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void EncryptDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void EncryptDlg::initialize()
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

void EncryptDlg::keyTypeChanged( int index )
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[1];
    CK_ULONG uCnt = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;
    mMechCombo->clear();

    if( index == 0 )
    {
        objClass = CKO_SECRET_KEY;
        mMechCombo->addItems(sMechList);
    }
    else if( index == 1 )
    {
        objClass = CKO_PUBLIC_KEY;
        mMechCombo->addItems(sPublicMechList);
    }

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    JS_PKCS11_FindObjectsInit( p11_ctx, sTemplate, uCnt );
    JS_PKCS11_FindObjects( p11_ctx, sObjects, uMaxObjCnt, &uObjCnt );
    JS_PKCS11_FindObjectsFinal( p11_ctx );

    mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char    *pStr = NULL;
        BIN binLabel = {0,0};
        JS_PKCS11_GetAtrributeValue2( p11_ctx, sObjects[i], CKA_LABEL, &binLabel );
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

void EncryptDlg::clickInit()
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();

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

    rv = JS_PKCS11_EncryptInit( p11_ctx, &sMech, hObject );

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
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();

    QString strInput = mInputText->text();

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


    rv = JS_PKCS11_EncryptUpdate( p11_ctx, binInput.pVal, binInput.nLen, pEncPart, (CK_ULONG_PTR)&uEncPartLen );

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
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();

    unsigned char *pEncPart = NULL;
    long uEncPartLen = 0;

    pEncPart = (unsigned char *)JS_malloc( mInputText->text().length() / 2 + 64 );
    if( pEncPart == NULL ) return;

    BIN binEncPart = {0,0};
    char *pHex = NULL;

    rv = JS_PKCS11_EncryptFinal( p11_ctx, pEncPart, (CK_ULONG_PTR)&uEncPartLen);
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
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();

    QString strInput = mInputText->text();

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


    rv = JS_PKCS11_Encrypt( p11_ctx, binInput.pVal, binInput.nLen, pEncData, (CK_ULONG_PTR)&uEncDataLen);

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
