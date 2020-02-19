#include "common.h"
#include "edit_attribute_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

static QStringList sAttributeList = {
    "CKA_LABEL", "CKA_APPLICATION", "CKA_VALUE", "CKA_OBJECT_ID",
    "CKA_ISSUER", "CKA_SERIAL_NUMBER", "CKA_TRUSTED", "CKA_SUBJECT",
    "CKA_ID", "CKA_SENSITIVE", "CKA_ENCRYPT", "CKA_DECRYPT",
    "CKA_WRAP", "CKA_UNWRAP", "CKA_SIGN", "CKA_SIGN_RECOVER",
    "CKA_VERIFY", "CKA_VERIFY_RECOVER", "CKA_DERIVE", "CKA_START_DATE",
    "CKA_END_DATE", "CKA_MODULUS", "CKA_PUBLIC_EXPONENT", "CKA_PRIVATE_EXPONENT",
    "CKA_PRIME_1", "CKA_PRIME_2", "CKA_EXPONENT_1", "CKA_EXPONENT_2",
    "CKA_COEFFICIENT", "CKA_PRIME", "CKA_SUBPRIME", "CKA_BASE",
    "CKA_EXTRACTABLE", "CKA_TOKEN", "CKA_PRIVATE", "CKA_MODIFIABLE"
};

EditAttributeDlg::EditAttributeDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    connect( mObjectCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(objectChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));

    connect( mCloseBtn, SIGNAL(clicked(bool)), this, SLOT(clickClose()));
    connect( mGetAttrBtn, SIGNAL(clicked(bool)), this, SLOT(clickGetAttribute()));
    connect( mSetAttrBtn, SIGNAL(clicked(bool)), this, SLOT(clickSetAttribute()));

    mObjectCombo->addItems(kObjectList);

    initialize();

}

EditAttributeDlg::~EditAttributeDlg()
{

}

void EditAttributeDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void EditAttributeDlg::setSelectedObject(int index)
{
    if( index >= 0 ) mObjectCombo->setCurrentIndex(index);
}

void EditAttributeDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void EditAttributeDlg::labelChanged( int index )
{

    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}

void EditAttributeDlg::objectChanged( int index )
{
    if( manApplet == NULL ) return;
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    if( p11_ctx == NULL ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_SESSION_HANDLE   hSession = -1;
    int nSlotSel = mSlotsCombo->currentIndex();
    if( nSlotSel < 0 ) return;

    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[1];
    long uCount = 0;
    CK_OBJECT_CLASS objClass = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;

    if( index == OBJ_DATA_IDX )
        objClass = CKO_DATA;
    else if( index == OBJ_CERT_IDX )
        objClass = CKO_CERTIFICATE;
    else if( index == OBJ_PUBKEY_IDX )
        objClass = CKO_PUBLIC_KEY;
    else if( index == OBJ_PRIKEY_IDX )
        objClass = CKO_PRIVATE_KEY;
    else if( index == OBJ_SECRET_IDX )
        objClass = CKO_SECRET_KEY;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    JS_PKCS11_FindObjectsInit( p11_ctx, hSession, sTemplate, uCount );
    JS_PKCS11_FindObjects( p11_ctx, hSession, sObjects, uMaxObjCnt, &uObjCnt );
    JS_PKCS11_FindObjectsFinal( p11_ctx, hSession );

    mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        BIN binLabel = {0,0};
        char *pHex = NULL;

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, sObjects[i], CKA_LABEL, &binLabel );
        const QVariant objVal =  QVariant( (int)sObjects[i] );

        JS_BIN_string( &binLabel, &pHex );
        mLabelCombo->addItem( pHex, objVal );
        JS_BIN_reset(&binLabel);
    }

    if( uObjCnt > 0 )
    {
        QString strHandle = QString("%1").arg( sObjects[0] );
        mObjectText->setText( strHandle );
    }
}


void EditAttributeDlg::initialize()
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

void EditAttributeDlg::initAttributes()
{
    mAttributeCombo->addItems(sAttributeList);
}

void EditAttributeDlg::accept()
{
    QDialog::accept();
}

void EditAttributeDlg::clickClose()
{
    this->hide();
}

void EditAttributeDlg::clickGetAttribute()
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    hSession = slotInfo.getSessionHandle();

    long hObject = mObjectText->text().toLong();

    if( hObject <= 0 )
    {
        manApplet->warningBox( tr("insert object handle"), this );
        return;
    }

    CK_ATTRIBUTE_TYPE attrType = 0;

    int nAttrPos = mAttributeCombo->currentIndex();
    attrType = JS_PKCS11_GetCKAType(sAttributeList.at(nAttrPos).toStdString().c_str());

    BIN binVal = {0,0};
    char *pHex = NULL;
    rv = JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObject, attrType, &binVal );
    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to get attributes(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    JS_BIN_encodeHex( &binVal, &pHex );
    JS_BIN_reset( &binVal );

    mValueText->setText( pHex );
    if( pHex ) JS_free(pHex);
}

void EditAttributeDlg::clickSetAttribute()
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    hSession = slotInfo.getSessionHandle();
    long hObject = mObjectText->text().toLong();

    if( hObject <= 0 )
    {
        manApplet->warningBox( tr("insert object handle"), this );
        return;
    }

    CK_ATTRIBUTE_TYPE attrType = 0;

    int nAttrPos = mAttributeCombo->currentIndex();
    attrType = JS_PKCS11_GetCKAType( sAttributeList.at(nAttrPos).toStdString().c_str());


    BIN binVal = {0,0};
    QString strValue = mValueText->toPlainText();

    JS_BIN_decodeHex( strValue.toStdString().c_str(), &binVal );

    rv = JS_PKCS11_SetAttributeValue2( p11_ctx, hSession, hObject, attrType, &binVal );
    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to set attributes(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("success to set attributes"), this );
    QMessageBox::information( this ,"EditAttribute", "SetAttribute success" );
}
