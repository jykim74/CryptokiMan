#include <QFileDialog>

#include "wrap_key_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"
#include "common.h"
#include "cryptoki_api.h"

static QStringList sWrappingMechList = {
    "CKM_RSA_PKCS", "CKM_RSA_PKCS_OAEP",
    "CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_PAD"
};

WrapKeyDlg::WrapKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    session_ = -1;

    setupUi(this);
    initUI();
}

WrapKeyDlg::~WrapKeyDlg()
{

}

void WrapKeyDlg::initUI()
{
    mWrappingMechCombo->addItems(sWrappingMechList);

    connect( mWrappingLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(wrappingLabelChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));

    initialize();
}

void WrapKeyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    slot_index_ = index;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    session_ = slotInfo.getSessionHandle();
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );

    mSlotsCombo->clear();
    mSlotsCombo->addItem( slotInfo.getDesc() );
}

void WrapKeyDlg::setSelectedSlot(int index)
{
    slotChanged( index );

    setWrapLabelList();
}

void WrapKeyDlg::initialize()
{

}

void WrapKeyDlg::accept()
{
    int rv = -1;
    QString strPath = mPathText->text();

    if( strPath.isEmpty() )
    {
        QMessageBox::warning( this, "WrapKey", "You have to select file path to save." );
        return;
    }


    long hWrappingKey = mWrappingObjectText->text().toLong();
    long hKey = mObjectText->text().toLong();

    CK_MECHANISM sMech;

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = JS_PKCS11_GetCKMType( mWrappingMechCombo->currentText().toStdString().c_str());

    QString strParam = mWrappingParamText->text();
    BIN binParam = {0,0};

    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strPath.toStdString().c_str(), &binParam );
        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }

    CK_BYTE_PTR pData = NULL;
    CK_ULONG uDataLen = 0;

    rv = manApplet->cryptokiAPI()->WrapKey( session_, &sMech, hWrappingKey, hKey, pData, &uDataLen );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to wrap key(%1)").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    pData = (CK_BYTE_PTR)JS_malloc( uDataLen );
    if( pData == NULL ) return;

    rv = manApplet->cryptokiAPI()->WrapKey( session_, &sMech, hWrappingKey, hKey, pData, &uDataLen );

    if( rv != CKR_OK )
    {
        if( pData ) JS_free( pData );
        manApplet->warningBox( tr("fail to wrap key(%1)").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    BIN binWrapped = {0,0};
    JS_BIN_set( &binWrapped, pData, uDataLen );
    JS_BIN_fileWrite( &binWrapped, strPath.toStdString().c_str() );


    if( pData ) JS_free( pData );
    JS_BIN_reset( &binWrapped );

    manApplet->messageBox( "WrapKey is success", this );
    QDialog::accept();
}

void WrapKeyDlg::setWrapLabelList()
{
    int rv = -1;

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

    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
    if( rv != CKR_OK ) return;

    mLabelCombo->clear();
    mWrappingLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;

        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

        JS_BIN_string( &binLabel, &pLabel );

        mLabelCombo->addItem( pLabel, objVal );
        mWrappingLabelCombo->addItem( pLabel, objVal );

        if( pLabel ) JS_free( pLabel );
        JS_BIN_reset( &binLabel );
    }

    uCnt = 0;
    uObjCnt = 0;
    objClass = CKO_PUBLIC_KEY;
    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
    if( rv != CKR_OK ) return;

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

        JS_BIN_string( &binLabel, &pLabel );

        mLabelCombo->addItem( pLabel, objVal );
        mWrappingLabelCombo->addItem( pLabel, objVal );

        if( pLabel ) JS_free( pLabel );
        JS_BIN_reset( &binLabel );
    }

    int iKeyCnt = mLabelCombo->count();
    if( iKeyCnt > 0 )
    {
        QVariant objVal = mLabelCombo->itemData(0);

        QString strObject = QString("%1").arg( objVal.toInt() );


        mObjectText->setText( strObject );
        mWrappingObjectText->setText( strObject );
    }
}


void WrapKeyDlg::labelChanged(int index )
{
    QVariant objVal = mLabelCombo->itemData(index);

    QString strObject = QString("%1").arg( objVal.toInt() );
    mObjectText->setText( strObject );
}

void WrapKeyDlg::wrappingLabelChanged(int index )
{
    QVariant objVal = mWrappingLabelCombo->itemData(index);

    QString strObject = QString("%1").arg( objVal.toInt() );

    mWrappingObjectText->setText( strObject );
}

void WrapKeyDlg::clickFind()
{
    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mPathText->setText( fileName );
}
