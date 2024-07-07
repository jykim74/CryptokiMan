/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "common.h"
#include "edit_attribute_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"

const QStringList kTypeList = { "String", "Hex", "Base64" };


EditAttributeDlg::EditAttributeDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    object_type_ = -1;
    object_id_ = -1;
    session_ = -1;
    attr_name_ = "";

    setupUi(this);

    connect( mObjectTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(objectTypeChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));

    connect( mCloseBtn, SIGNAL(clicked(bool)), this, SLOT(clickClose()));
    connect( mGetAttrBtn, SIGNAL(clicked(bool)), this, SLOT(clickGetAttribute()));
    connect( mSetAttrBtn, SIGNAL(clicked(bool)), this, SLOT(clickSetAttribute()));

    connect( mValueText, SIGNAL(textChanged()), this, SLOT(changeValue()));
    connect( mValueTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeValue()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

EditAttributeDlg::~EditAttributeDlg()
{

}

void EditAttributeDlg::setSlotIndex( int index )
{
    slotChanged( index );
}

void EditAttributeDlg::setObjectType( int type )
{
    object_type_ = type;
}

void EditAttributeDlg::setObjectID( long id )
{
    object_id_ = id;
}

void EditAttributeDlg::setAttrName( const QString& strName )
{
    attr_name_ = strName;
}

void EditAttributeDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    slot_index_ = index;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo;

    slotInfo = slot_infos.at( index );

    session_ = slotInfo.getSessionHandle();

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );

    mSlotsCombo->clear();
    mSlotsCombo->addItem( slotInfo.getDesc() );
    mSlotsCombo->setAcceptDrops(false);
}

void EditAttributeDlg::labelChanged( int index )
{

    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}

void EditAttributeDlg::objectTypeChanged( int type )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[1];
    long uCount = 0;
    CK_OBJECT_CLASS objClass = 0;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE sObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

    mAttributeCombo->clear();
    mAttributeCombo->addItems( kCommonAttList );

    if( type == OBJ_DATA_IDX )
    {
        objClass = CKO_DATA;
        mAttributeCombo->addItems( kDataAttList );
    }
    else if( type == OBJ_CERT_IDX )
    {
        objClass = CKO_CERTIFICATE;
        mAttributeCombo->addItems( kCommonCertAttList );
        mAttributeCombo->addItems( kX509CertAttList );
    }
    else if( type == OBJ_PUBKEY_IDX )
    {
        objClass = CKO_PUBLIC_KEY;
        mAttributeCombo->addItems( kCommonKeyAttList );
        mAttributeCombo->addItems( kPubKeyAttList );
    }
    else if( type == OBJ_PRIKEY_IDX )
    {
        objClass = CKO_PRIVATE_KEY;
        mAttributeCombo->addItems( kCommonKeyAttList );
        mAttributeCombo->addItems( kPriKeyAttList );
    }
    else if( type == OBJ_SECRET_IDX )
    {
        objClass = CKO_SECRET_KEY;
        mAttributeCombo->addItems( kCommonKeyAttList );
        mAttributeCombo->addItems( kSecretKeyAttList );
    }

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    if( object_id_ < 0 )
    {
        rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCount );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
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

        manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

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
    mValueTypeCombo->addItems( kTypeList );
    mValueTypeCombo->setCurrentText( "Hex" );

    if( manApplet->isLicense() == false )
        mSetAttrBtn->setEnabled( false );
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
    if( object_type_ < 0 )
        mObjectTypeCombo->addItems(kObjectTypeList);
    else
        mObjectTypeCombo->addItem( kObjectTypeList[object_type_] );

    if( attr_name_.length() > 0 )
    {
        mAttributeCombo->clear();
        mAttributeCombo->addItem( attr_name_ );

        QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

        int nSlotSel = mSlotsCombo->currentIndex();
        if( nSlotSel < 0 ) return;

        SlotInfo slotInfo;

        if( slot_index_ < 0 )
            slotInfo = slot_infos.at(nSlotSel);
        else
            slotInfo = slot_infos.at( slot_index_ );

        CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

        BIN binLabel = {0,0};
        char *pHex = NULL;

        manApplet->cryptokiAPI()->GetAttributeValue2( hSession, object_id_, CKA_LABEL, &binLabel );
        const QVariant objVal =  QVariant((int) object_id_ );
        JS_BIN_string( &binLabel, &pHex );
        mLabelCombo->clear();
        mLabelCombo->addItem( pHex, objVal );
        JS_BIN_reset(&binLabel);
        if( pHex ) JS_free( pHex );

        QString strHandle = QString("%1").arg( object_id_ );
        mObjectText->setText( strHandle );

        clickGetAttribute();
    }
    else
    {
        objectTypeChanged( object_type_ );
    }
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
    int rv = -1;

    long hObject = mObjectText->text().toLong();

    if( hObject <= 0 )
    {
        manApplet->warningBox( tr("Enter the handle value of the source"), this );
        return;
    }

    CK_ATTRIBUTE_TYPE attrType = 0;

    QString strAttrib = mAttributeCombo->currentText();
    attrType = JS_PKCS11_GetCKAType( strAttrib.toStdString().c_str());

    BIN binVal = {0,0};
    QString strValue;

    rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, hObject, attrType, &binVal );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("GetAttributeValue2 execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

//    JS_BIN_encodeHex( &binVal, &pHex );

    strValue = getStringFromBIN( &binVal, mValueTypeCombo->currentText() );
    JS_BIN_reset( &binVal );

    mValueText->setText( strValue );
}

void EditAttributeDlg::clickSetAttribute()
{
    int rv = -1;
    long hObject = mObjectText->text().toLong();

    if( hObject <= 0 )
    {
        manApplet->warningBox( tr("Enter the handle value of the source"), this );
        return;
    }

    CK_ATTRIBUTE_TYPE attrType = 0;

    QString strAttrib = mAttributeCombo->currentText();
    attrType = JS_PKCS11_GetCKAType( strAttrib.toStdString().c_str() );


    BIN binVal = {0,0};
    QString strValue = mValueText->toPlainText();

    getBINFromString( &binVal, mValueTypeCombo->currentText(), strValue );

    rv = manApplet->cryptokiAPI()->SetAttributeValue2( session_, hObject, attrType, &binVal );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("SetAttributeValue2 execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("SetAttributeValue2 execution successful"), this );
    QMessageBox::information( this ,"EditAttribute", "SetAttribute success" );
}

void EditAttributeDlg::changeValue()
{
    QString strValue = mValueText->toPlainText();

    int nLen = getDataLen( mValueTypeCombo->currentText(), strValue );
    mValueLenText->setText( QString( "%1" ).arg(nLen) );
}
