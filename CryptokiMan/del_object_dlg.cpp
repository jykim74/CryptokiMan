/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "del_object_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

#include "common.h"
#include "man_tree_item.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"

DelObjectDlg::DelObjectDlg(QWidget *parent) :
    QDialog(parent)
{
    object_type_ = -1;
    object_id_ = -1;
    slot_index_ = -1;
    session_  = -1;

    setupUi(this);

    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));
    /* need to check for being crashed */
    connect( mObjectTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(objectTypeChanged(int)));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mDeleteBtn, SIGNAL(clicked()), this, SLOT(deleteObj()));
    connect( mDeleteAllBtn, SIGNAL(clicked()), this, SLOT(deleteAllObj()));
}

DelObjectDlg::~DelObjectDlg()
{

}

void DelObjectDlg::setSlotIndex( int index )
{
    slotChanged( index );
}

void DelObjectDlg::setObjectType( int type )
{
    object_type_ = type;
}

void DelObjectDlg::setObjectID( long id )
{
    object_id_ = id;
}

void DelObjectDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    slot_index_ = index;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo;

    if( slot_infos.size() <= index ) return;

    slotInfo = slot_infos.at(index);
    session_ = slotInfo.getSessionHandle();

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );

    mSlotsCombo->clear();
    mSlotsCombo->addItem( slotInfo.getDesc() );
}

void DelObjectDlg::initialize()
{
//    if( object_id_ >= 0 ) mDeleteAllBtn->setDisabled(true);
}

void DelObjectDlg::showEvent(QShowEvent *event)
{
    if( object_type_ < 0 )
        mObjectTypeCombo->addItems(kObjectTypeList);
    else
        mObjectTypeCombo->addItem(kObjectTypeList[object_type_]);

    initialize();

    objectTypeChanged( object_type_ );
}

void DelObjectDlg::closeEvent(QCloseEvent *)
{

}

void DelObjectDlg::deleteObj()
{
    int rv = -1;

    long hObject = mObjectText->text().toLong();

    rv = manApplet->cryptokiAPI()->DestroyObject( session_, hObject );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("DestroyObject execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("DestroyObject execution successful"), this );

    QString strType = mObjectTypeCombo->currentText();
    int nDataType = -1;

    if( strType == kObjectTypeList[0] )
    {
        nDataType = HM_ITEM_TYPE_CERTIFICATE;
    }
    else if( strType == kObjectTypeList[1] )
    {
        nDataType = HM_ITEM_TYPE_PUBLICKEY;
    }
    else if( strType == kObjectTypeList[2] )
    {
        nDataType = HM_ITEM_TYPE_PRIVATEKEY;
    }
    else if( strType == kObjectTypeList[3] )
    {
        nDataType = HM_ITEM_TYPE_SECRETKEY;
    }
    else if( strType == kObjectTypeList[4] )
    {
        nDataType = HM_ITEM_TYPE_DATA;
    }

    manApplet->showTypeList( slot_index_, nDataType );
    QDialog::accept();
}

void DelObjectDlg::deleteAllObj()
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[1];
    long uCount = 0;
    CK_OBJECT_CLASS objClass = 0;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE sObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;
    int nDataType = -1;

    QString strType = mObjectTypeCombo->currentText();

    bool bVal = manApplet->yesOrNoBox( tr( "Are you sure to delete %1 objects all?").arg( strType ), this, false );
    if( bVal == false ) return;

    if( strType == kObjectTypeList[0] )
    {
        objClass = CKO_CERTIFICATE;
        nDataType = HM_ITEM_TYPE_CERTIFICATE;
    }
    else if( strType == kObjectTypeList[1] )
    {
        objClass = CKO_PUBLIC_KEY;
        nDataType = HM_ITEM_TYPE_PUBLICKEY;
    }
    else if( strType == kObjectTypeList[2] )
    {
        objClass = CKO_PRIVATE_KEY;
        nDataType = HM_ITEM_TYPE_PRIVATEKEY;
    }
    else if( strType == kObjectTypeList[3] )
    {
        objClass = CKO_SECRET_KEY;
        nDataType = HM_ITEM_TYPE_SECRETKEY;
    }
    else if( strType == kObjectTypeList[4] )
    {
        objClass = CKO_DATA;
        nDataType = HM_ITEM_TYPE_DATA;
    }
    else
    {
        manApplet->warningBox( tr( "invalid object type[%1]").arg( strType ));
        return;
    }

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCount );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
    if( rv != CKR_OK ) return;

    mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        rv = manApplet->cryptokiAPI()->DestroyObject( session_, sObjects[i] );
        if( rv != CKR_OK )
        {
            manApplet->elog( QString( "DestoryObject execution failure [%1]").arg( sObjects[i] ));
            break;
        }
        else
        {
            manApplet->log( QString( "The object(%1) has been deleted").arg( sObjects[i] ));
        }
    }

    manApplet->showTypeList( slot_index_, nDataType );

    if( rv == CKR_OK)
        QDialog::accept();
    else
        QDialog::reject();
}


void DelObjectDlg::labelChanged( int index )
{

    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}

void DelObjectDlg::objectTypeChanged( int type )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[1];
    long uCount = 0;
    CK_OBJECT_CLASS objClass = 0;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE sObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

    if( type == OBJ_DATA_IDX )
        objClass = CKO_DATA;
    else if( type == OBJ_CERT_IDX )
        objClass = CKO_CERTIFICATE;
    else if( type == OBJ_PUBKEY_IDX )
        objClass = CKO_PUBLIC_KEY;
    else if( type == OBJ_PRIKEY_IDX )
        objClass = CKO_PRIVATE_KEY;
    else if( type == OBJ_SECRET_IDX )
        objClass = CKO_SECRET_KEY;

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

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

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
