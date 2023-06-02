#include "digest_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"

static QStringList sMechList = {
    "CKM_MD5", "CKM_SHA_1", "CKM_SHA256", "CKM_SHA512"
};

static QStringList sInputList = {
    "String", "Hex", "Base64"
};

DigestDlg::DigestDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
    initialize();
}

DigestDlg::~DigestDlg()
{

}

void DigestDlg::initUI()
{
    mMechCombo->addItems( sMechList );
    mInputCombo->addItems( sInputList );

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT( slotChanged(int) ));
    connect( mKeyLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT( changeKeyLabel(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mDigestKeyBtn, SIGNAL(clicked()), this, SLOT(clickDigestKey()));
    connect( mDigestBtn, SIGNAL(clicked()), this, SLOT(clickDigest()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));

}

long DigestDlg::getSessinHandle()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    return hSession;
}

void DigestDlg::setKeyList()
{
    int rv = -1;

    CK_SESSION_HANDLE hSession = getSessinHandle();

    CK_ATTRIBUTE sTemplate[1];
    CK_ULONG uCnt = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;

    objClass = CKO_SECRET_KEY;

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

    mKeyLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;

        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, sObjects[i], CKA_LABEL, &binLabel );

        JS_BIN_string( &binLabel, &pLabel );

        mKeyLabelCombo->addItem( pLabel, objVal );

        if( pLabel ) JS_free( pLabel );
        JS_BIN_reset( &binLabel );
    }
}

void DigestDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void DigestDlg::changeKeyLabel( int index )
{
    QVariant objVal = mKeyLabelCombo->itemData(index);

    QString strObject = QString("%1").arg( objVal.toInt() );
    mKeyObjectText->setText( strObject );
}

void DigestDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);

    setKeyList();
}


void DigestDlg::initialize()
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

void DigestDlg::clickDigestKey()
{
    int rv;
    CK_SESSION_HANDLE hSession = getSessinHandle();
    CK_OBJECT_HANDLE hKey = mKeyObjectText->text().toULong();

    rv = manApplet->cryptokiAPI()->DigestKey( hSession, hKey );
}

void DigestDlg::clickInit()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    BIN binParam = {0,0};
    CK_MECHANISM stMech;

    memset( &stMech, 0x00, sizeof(stMech) );

    int iPos = mMechCombo->currentIndex();
    stMech.mechanism = JS_PKCS11_GetCKMType( sMechList.at(iPos).toStdString().c_str());

    QString strParam = mParamText->text();
    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam);
        stMech.pParameter = binParam.pVal;
        stMech.ulParameterLen = binParam.nLen;
    }

    rv = manApplet->cryptokiAPI()->DigestInit( hSession, &stMech );

    if( rv == CKR_OK )
    {
        mStatusLabel->setText( "Init" );
        mOutputText->setText( "" );
    }
    else
    {
        manApplet->warningBox( tr("fail to run DigestInit(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        mStatusLabel->setText("");
        mOutputText->setText("");
    }
}

void DigestDlg::clickUpdate()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    QString strInput = mInputText->toPlainText();
    if( strInput.isEmpty() )
    {
        manApplet->warningBox(tr("Insert input value."), this );
        mInputText->setFocus();

        return;
    }

    BIN binInput = {0,0};
    if( mInputCombo->currentIndex() == 0 )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    rv = manApplet->cryptokiAPI()->DigestUpdate( hSession, binInput.pVal, binInput.nLen );

    if( rv == CKR_OK )
    {
        QString strMsg = mStatusLabel->text();
        strMsg += "|Update";

        mStatusLabel->setText( strMsg );
    }
    else
    {
        manApplet->warningBox( tr("fail to run DigestUpdate(%1)").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        mOutputText->setText("");
    }
}

void DigestDlg::clickFinal()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();


    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();


    unsigned char sDigest[512];
    CK_ULONG uDigestLen = 64;
    BIN binDigest = {0,0};

    memset( sDigest, 0x00, sizeof(sDigest) );

    rv = manApplet->cryptokiAPI()->DigestFinal( hSession, sDigest, &uDigestLen );

    if( rv == CKR_OK )
    {
        char *pHex = NULL;
        JS_BIN_set( &binDigest, sDigest, uDigestLen );
        JS_BIN_encodeHex( &binDigest, &pHex );
        mOutputText->setText( pHex );
        QString strResult = mStatusLabel->text();
        strResult += "|Final";
        mStatusLabel->setText(strResult);
        if( pHex ) JS_free(pHex);
    }
    else
    {
        manApplet->warningBox( tr("fail to run DigestFinal(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        mOutputText->setText("");
    }
}

void DigestDlg::clickDigest()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    QString strInput = mInputText->toPlainText();
    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert input value"), this );
        return;
    }

    BIN binInput = {0,0};

    if( mInputCombo->currentIndex() == 0 )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput);
    else if( mInputCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    unsigned char sDigest[512];
    CK_ULONG uDigestLen = 64;
    BIN binDigest = {0,0};

    memset( sDigest, 0x00, sizeof(sDigest) );

    rv = manApplet->cryptokiAPI()->Digest( hSession, binInput.pVal, binInput.nLen, sDigest, &uDigestLen );

    if( rv == CKR_OK )
    {
        char *pHex = NULL;
        JS_BIN_set( &binDigest, sDigest, uDigestLen );
        JS_BIN_encodeHex( &binDigest, &pHex );
        mOutputText->setText( pHex );

        QString strRes = mStatusLabel->text();
        strRes += "|Digest";
        mStatusLabel->setText(strRes);
    }
    else
    {
        manApplet->warningBox( tr("fail run Digest(%1)").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        mOutputText->setText("");
    }
}

void DigestDlg::clickClose()
{
    this->hide();
}
