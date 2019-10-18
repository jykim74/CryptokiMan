#include "encrypt_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

static QStringList sMechList = {
    "CKM_DES3_ECB", "CKM_DES3_CBC", "CKM_AES_ECB", "CKM_AES_CBC",
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

void EncryptDlg::showEvent(QShowEvent* event )
{
    initialize();
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
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[1];
    CK_ULONG uCnt = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;

    if( index == 0 )
        objClass = CKO_SECRET_KEY;
    else if( index == 1 )
        objClass = CKO_PUBLIC_KEY;

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

void EncryptDlg::labelChanged( int index )
{
    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}

void EncryptDlg::clickInit()
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

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

    rv = JS_PKCS11_EncryptInit( p11_ctx, hSession, &sMech, hObject );

    if( rv != CKR_OK )
    {
        mStatusLabel->setText("");
        mOutputText->setPlainText("");
        return;
    }

    mStatusLabel->setText( "Init" );
    mOutputText->setPlainText( "" );
}

void EncryptDlg::clickUpdate()
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

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
    long uEncPartLen = 0;

    pEncPart = (unsigned char *)JS_malloc( binInput.nLen + 64 );
    if( pEncPart == NULL ) return;


    rv = JS_PKCS11_EncryptUpdate( p11_ctx, hSession, binInput.pVal, binInput.nLen, pEncPart, (CK_ULONG_PTR)&uEncPartLen );

    if( rv != 0 )
    {
        mOutputText->setPlainText("");
        if( pEncPart ) JS_free( pEncPart );
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

    if( pEncPart ) JS_free( pEncPart );
    if( pHex ) JS_free( pHex );
}

void EncryptDlg::clickFinal()
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

    unsigned char *pEncPart = NULL;
    long uEncPartLen = 0;

    pEncPart = (unsigned char *)JS_malloc( mInputText->text().length() / 2 + 64 );
    if( pEncPart == NULL ) return;

    BIN binEncPart = {0,0};
    char *pHex = NULL;

    rv = JS_PKCS11_EncryptFinal( p11_ctx, hSession, pEncPart, (CK_ULONG_PTR)&uEncPartLen);
    if( rv != CKR_OK )
    {
        mOutputText->setPlainText( "" );
        if( pEncPart ) JS_free( pEncPart );
        return;
    }


    JS_BIN_set( &binEncPart, pEncPart, uEncPartLen );
    JS_BIN_encodeHex( &binEncPart, &pHex );

    QString strRes = mStatusLabel->text();
    strRes += "|Final";

    mOutputText->setPlainText( pHex );
    mStatusLabel->setText( strRes );
    if( pEncPart ) JS_free( pEncPart );
    if( pHex ) JS_free(pHex);
    JS_BIN_reset( &binEncPart );
}

void EncryptDlg::clickEncrypt()
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

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
    long uEncDataLen = 0;
    BIN binEncData = {0,0};

    pEncData = (unsigned char *)JS_malloc( binInput.nLen + 64 );
    if( pEncData == NULL ) return;


    rv = JS_PKCS11_Encrypt( p11_ctx, hSession, binInput.pVal, binInput.nLen, pEncData, (CK_ULONG_PTR)&uEncDataLen);

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText( "" );
        if( pEncData ) JS_free( pEncData );
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
