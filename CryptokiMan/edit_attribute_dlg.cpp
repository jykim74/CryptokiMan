#include "common.h"
#include "edit_attribute_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"


EditAttributeDlg::EditAttributeDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    object_index_ = -1;
    object_id_ = -1;

    setupUi(this);

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    connect( mObjectCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(objectChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));

    connect( mCloseBtn, SIGNAL(clicked(bool)), this, SLOT(clickClose()));
    connect( mGetAttrBtn, SIGNAL(clicked(bool)), this, SLOT(clickGetAttribute()));
    connect( mSetAttrBtn, SIGNAL(clicked(bool)), this, SLOT(clickSetAttribute()));
}

EditAttributeDlg::~EditAttributeDlg()
{

}

void EditAttributeDlg::setSlotIndex( int index )
{
    slot_index_ = index;
}

void EditAttributeDlg::setObjectIndex( int index )
{
    object_index_ = index;
}

void EditAttributeDlg::setObjectID( long id )
{
    object_id_ = id;
}

void EditAttributeDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo;

    if( slot_index_ < 0 )
        slotInfo = slot_infos.at(index);
    else
        slotInfo = slot_infos.at( slot_index_ );

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

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nSlotSel = mSlotsCombo->currentIndex();
    if( nSlotSel < 0 ) return;

    SlotInfo slotInfo;

    if( slot_index_ < 0 )
        slotInfo = slot_infos.at(nSlotSel);
    else
        slotInfo = slot_infos.at( slot_index_ );

    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[1];
    long uCount = 0;
    CK_OBJECT_CLASS objClass = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;

    mAttributeCombo->clear();
    mAttributeCombo->addItems( kCommonAttList );

    if( index == OBJ_DATA_IDX )
    {
        objClass = CKO_DATA;
        mAttributeCombo->addItems( kDataAttList );
    }
    else if( index == OBJ_CERT_IDX )
    {
        objClass = CKO_CERTIFICATE;
        mAttributeCombo->addItems( kCertAttList );
    }
    else if( index == OBJ_PUBKEY_IDX )
    {
        objClass = CKO_PUBLIC_KEY;
        mAttributeCombo->addItems( kPubKeyAttList );
    }
    else if( index == OBJ_PRIKEY_IDX )
    {
        objClass = CKO_PRIVATE_KEY;
        mAttributeCombo->addItems( kPriKetAttList );
    }
    else if( index == OBJ_SECRET_IDX )
    {
        objClass = CKO_SECRET_KEY;
        mAttributeCombo->addItems( kSecretKeyAttList );
    }

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    if( object_id_ < 0 )
    {
        rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, sTemplate, uCount );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjects( hSession, sObjects, uMaxObjCnt, &uObjCnt );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
        if( rv != CKR_OK ) return;
    }
    else
    {
        uObjCnt = 1;
        sObjects[0] = object_id_;
    }

    mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        BIN binLabel = {0,0};
        char *pHex = NULL;

        manApplet->cryptokiAPI()->GetAttributeValue2( hSession, sObjects[i], CKA_LABEL, &binLabel );

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

    if( slot_index_ < 0 )
    {
        for( int i=0; i < slot_infos.size(); i++ )
        {
            SlotInfo slotInfo = slot_infos.at(i);

            mSlotsCombo->addItem( slotInfo.getDesc() );
        }

        if( slot_infos.size() > 0 ) slotChanged(0);
    }
    else
    {
        SlotInfo slotInfo = slot_infos.at(slot_index_);
        mSlotsCombo->addItem( slotInfo.getDesc() );
    }

}

void EditAttributeDlg::initAttributes()
{
//    mAttributeCombo->addItems(sAttributeList);
    mAttributeCombo->addItems( kCommonAttList );
}

void EditAttributeDlg::accept()
{
    QDialog::accept();
}

void EditAttributeDlg::showEvent(QShowEvent *event)
{
    initAttributes();
    if( object_index_ < 0 )
        mObjectCombo->addItems(kObjectList);
    else
        mObjectCombo->addItem( kObjectList[object_index_] );

    initialize();

//    if( slot_index_ >= 0 ) mSlotsCombo->setCurrentIndex( slot_index_ );
    objectChanged( object_index_ );
}

void EditAttributeDlg::closeEvent(QCloseEvent *)
{

}

void EditAttributeDlg::clickClose()
{
    this->hide();
}

void EditAttributeDlg::clickGetAttribute()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    long hObject = mObjectText->text().toLong();

    if( hObject <= 0 )
    {
        manApplet->warningBox( tr("insert object handle"), this );
        return;
    }

    CK_ATTRIBUTE_TYPE attrType = 0;

    QString strAttrib = mAttributeCombo->currentText();
    attrType = JS_PKCS11_GetCKAType( strAttrib.toStdString().c_str());

    BIN binVal = {0,0};
    char *pHex = NULL;

    rv = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObject, attrType, &binVal );

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
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();


    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();
    long hObject = mObjectText->text().toLong();

    if( hObject <= 0 )
    {
        manApplet->warningBox( tr("insert object handle"), this );
        return;
    }

    CK_ATTRIBUTE_TYPE attrType = 0;

    QString strAttrib = mAttributeCombo->currentText();
    attrType = JS_PKCS11_GetCKAType( strAttrib.toStdString().c_str() );


    BIN binVal = {0,0};
    QString strValue = mValueText->toPlainText();

    JS_BIN_decodeHex( strValue.toStdString().c_str(), &binVal );

    rv = manApplet->cryptokiAPI()->SetAttributeValue2( hSession, hObject, attrType, &binVal );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to set attributes(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("success to set attributes"), this );
    QMessageBox::information( this ,"EditAttribute", "SetAttribute success" );
}
