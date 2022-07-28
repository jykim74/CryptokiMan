#include "del_object_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

#include "common.h"
#include "man_tree_item.h"
#include "cryptoki_api.h"

DelObjectDlg::DelObjectDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    object_index_ = -1;
    object_id_ = -1;

    setupUi(this);

    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));
    /* need to check for being crashed */
    connect( mObjectCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(objectChanged(int)));
    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mDeleteBtn, SIGNAL(clicked()), this, SLOT(deleteObj()));
    connect( mDeleteAllBtn, SIGNAL(clicked()), this, SLOT(deleteAllObj()));

}

DelObjectDlg::~DelObjectDlg()
{

}

void DelObjectDlg::setSlotIndex( int index )
{
    slot_index_ = index;
}

void DelObjectDlg::setObjectIndex( int index )
{
    object_index_ = index;
}

void DelObjectDlg::setObjectID( long id )
{
    object_id_ = id;
}

void DelObjectDlg::slotChanged(int index)
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

void DelObjectDlg::initialize()
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

    if( object_id_ >= 0 ) mDeleteAllBtn->setDisabled(true);
}

void DelObjectDlg::showEvent(QShowEvent *event)
{
    if( object_index_ < 0 )
        mObjectCombo->addItems(kObjectList);
    else
        mObjectCombo->addItem(kObjectList[object_index_]);

    initialize();

    objectChanged( object_index_ );
}

void DelObjectDlg::closeEvent(QCloseEvent *)
{

}

void DelObjectDlg::deleteObj()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();


    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo;

    if( slot_index_ < 0 )
        slotInfo = slot_infos.at(index);
    else
        slotInfo = slot_infos.at( slot_index_ );

    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    long hObject = mObjectText->text().toLong();

    rv = manApplet->cryptokiAPI()->DestroyObject( hSession, hObject );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to delete object(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("success to delete object"), this );

    QString strType = mObjectCombo->currentText();
    int nDataType = -1;

    if( strType == kObjectList[0] )
    {
        nDataType = HM_ITEM_TYPE_DATA;
    }
    else if( strType == kObjectList[1] )
    {
        nDataType = HM_ITEM_TYPE_CERTIFICATE;
    }
    else if( strType == kObjectList[2] )
    {
        nDataType = HM_ITEM_TYPE_PUBLICKEY;
    }
    else if( strType == kObjectList[3] )
    {
        nDataType = HM_ITEM_TYPE_PRIVATEKEY;
    }
    else if( strType == kObjectList[4] )
    {
        nDataType = HM_ITEM_TYPE_SECRETKEY;
    }

    manApplet->showTypeData( slot_index_, nDataType );
    QDialog::accept();
}

void DelObjectDlg::deleteAllObj()
{
    if( manApplet == NULL ) return;
    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();


    int nSlotSel = mSlotsCombo->currentIndex();
    if( nSlotSel < 0 ) return;

    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[1];
    long uCount = 0;
    CK_OBJECT_CLASS objClass = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;
    int nDataType = -1;

    QString strType = mObjectCombo->currentText();

    if( strType == kObjectList[0] )
    {
        objClass = CKO_DATA;
        nDataType = HM_ITEM_TYPE_DATA;
    }
    else if( strType == kObjectList[1] )
    {
        objClass = CKO_CERTIFICATE;
        nDataType = HM_ITEM_TYPE_CERTIFICATE;
    }
    else if( strType == kObjectList[2] )
    {
        objClass = CKO_PUBLIC_KEY;
        nDataType = HM_ITEM_TYPE_PUBLICKEY;
    }
    else if( strType == kObjectList[3] )
    {
        objClass = CKO_PRIVATE_KEY;
        nDataType = HM_ITEM_TYPE_PRIVATEKEY;
    }
    else if( strType == kObjectList[4] )
    {
        objClass = CKO_SECRET_KEY;
        nDataType = HM_ITEM_TYPE_SECRETKEY;
    }

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, sTemplate, uCount );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( hSession, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
    if( rv != CKR_OK ) return;

    mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        rv = manApplet->cryptokiAPI()->DestroyObject( hSession, sObjects[i] );
    }

    manApplet->showTypeData( nSlotSel, nDataType );

    QDialog::accept();
}


void DelObjectDlg::labelChanged( int index )
{

    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}

void DelObjectDlg::objectChanged( int index )
{
    if( manApplet == NULL ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();


    int nSlotSel = mSlotsCombo->currentIndex();
    if( nSlotSel < 0 ) return;

    SlotInfo slotInfo;

    if( slot_index_ < 0 )
        slotInfo = slot_infos.at(nSlotSel);
    else
        slotInfo = slot_infos.at(slot_index_);

    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

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

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, sObjects[i], CKA_LABEL, &binLabel );

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
