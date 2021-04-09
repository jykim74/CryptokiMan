#include "del_object_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

#include "common.h"
#include "man_tree_item.h"

DelObjectDlg::DelObjectDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));
    /* need to check for being crashed */
    connect( mObjectCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(objectChanged(int)));
    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mDeleteBtn, SIGNAL(clicked()), this, SLOT(deleteObj()));
    connect( mDeleteAllBtn, SIGNAL(clicked()), this, SLOT(deleteAllObj()));

    mObjectCombo->addItems(kObjectList);

    initialize();
}

DelObjectDlg::~DelObjectDlg()
{

}

void DelObjectDlg::setSeletedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void DelObjectDlg::setSelectedObject(int index)
{
    if( index >= 0 ) mObjectCombo->setCurrentIndex(index);
}

void DelObjectDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void DelObjectDlg::initialize()
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

void DelObjectDlg::deleteObj()
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();

    long hObject = mObjectText->text().toLong();

    rv = JS_PKCS11_DestroyObject( p11_ctx, hObject );
    manApplet->logP11Result( "C_DestroyObject", rv );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to delete object(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("success to delete object"), this );
    QDialog::accept();
}

void DelObjectDlg::deleteAllObj()
{
    if( manApplet == NULL ) return;
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    if( p11_ctx == NULL ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();


    int nSlotSel = mSlotsCombo->currentIndex();
    if( nSlotSel < 0 ) return;

    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[1];
    long uCount = 0;
    CK_OBJECT_CLASS objClass = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;
    int nDataType = -1;

    int type = mObjectCombo->currentIndex();

    if( type == OBJ_DATA_IDX )
    {
        objClass = CKO_DATA;
        nDataType = HM_ITEM_TYPE_DATA;
    }
    else if( type == OBJ_CERT_IDX )
    {
        objClass = CKO_CERTIFICATE;
        nDataType = HM_ITEM_TYPE_CERTIFICATE;
    }
    else if( type == OBJ_PUBKEY_IDX )
    {
        objClass = CKO_PUBLIC_KEY;
        nDataType = HM_ITEM_TYPE_PUBLICKEY;
    }
    else if( type == OBJ_PRIKEY_IDX )
    {
        objClass = CKO_PRIVATE_KEY;
        nDataType = HM_ITEM_TYPE_PRIVATEKEY;
    }
    else if( type == OBJ_SECRET_IDX )
    {
        objClass = CKO_SECRET_KEY;
        nDataType = HM_ITEM_TYPE_SECRETKEY;
    }

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    manApplet->logTemplate( sTemplate, uCount );

    rv = JS_PKCS11_FindObjectsInit( p11_ctx, sTemplate, uCount );
    manApplet->logP11Result( "C_FindObjectsInit", rv );

    rv = JS_PKCS11_FindObjects( p11_ctx, sObjects, uMaxObjCnt, &uObjCnt );
    manApplet->logP11Result( "C_FindObjects", rv );

    rv = JS_PKCS11_FindObjectsFinal( p11_ctx );
    manApplet->logP11Result( "C_FindObjectsFinal", rv );

    mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        rv = JS_PKCS11_DestroyObject( p11_ctx, sObjects[i] );
        manApplet->logP11Result( "C_DestroyObject", rv );
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
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    if( p11_ctx == NULL ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();


    int nSlotSel = mSlotsCombo->currentIndex();
    if( nSlotSel < 0 ) return;

    SlotInfo slotInfo = slot_infos.at(nSlotSel);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();

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

    manApplet->logTemplate( sTemplate, uCount );

    rv = JS_PKCS11_FindObjectsInit( p11_ctx, sTemplate, uCount );
    manApplet->logP11Result( "C_FindObjectsInit", rv );

    rv = JS_PKCS11_FindObjects( p11_ctx, sObjects, uMaxObjCnt, &uObjCnt );
    manApplet->logP11Result( "C_FindObjects", rv );

    rv = JS_PKCS11_FindObjectsFinal( p11_ctx );
    manApplet->logP11Result( "C_FindObjectsFinal", rv );

    mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        BIN binLabel = {0,0};
        char *pHex = NULL;

        rv = JS_PKCS11_GetAttributeValue2( p11_ctx, sObjects[i], CKA_LABEL, &binLabel );
        manApplet->logP11Result( "C_GetAttribute2", rv );

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
