#include <QFileDialog>

#include "wrap_key_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"

static QStringList sWrappingMechList = {
    "CKM_RSA_PKCS", "CKM_RSA_PKCS_OAEP",
    "CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_PAD"
};

WrapKeyDlg::WrapKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
}

WrapKeyDlg::~WrapKeyDlg()
{

}

void WrapKeyDlg::initUI()
{
    mWrappingMechCombo->addItems(sWrappingMechList);

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    connect( mWrappingLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(wrappingLabelChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));
    connect( mFindBtn, SIGNAL(clicked(bool)), this, SLOT(clickFind()));

    initialize();
    setWrapLabelList();
}

void WrapKeyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void WrapKeyDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void WrapKeyDlg::initialize()
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

void WrapKeyDlg::accept()
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    p11_ctx->hSession = slotInfo.getSessionHandle();

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

    rv = JS_PKCS11_WrapKey( p11_ctx, &sMech, hWrappingKey, hKey, pData, &uDataLen );
    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to wrap key(%1)").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    pData = (CK_BYTE_PTR)JS_malloc( uDataLen );
    if( pData == NULL ) return;

    rv = JS_PKCS11_WrapKey( p11_ctx, &sMech, hWrappingKey, hKey, pData, &uDataLen );
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
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    p11_ctx->hSession = slotInfo.getSessionHandle();

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


    JS_PKCS11_FindObjectsInit( p11_ctx, sTemplate, uCnt );
    JS_PKCS11_FindObjects( p11_ctx, sObjects, uMaxObjCnt, &uObjCnt );
    JS_PKCS11_FindObjectsFinal( p11_ctx );

    mLabelCombo->clear();
    mWrappingLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;

        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        JS_PKCS11_GetAtrributeValue2( p11_ctx, sObjects[i], CKA_LABEL, &binLabel );
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

    JS_PKCS11_FindObjectsInit( p11_ctx, sTemplate, uCnt );
    JS_PKCS11_FindObjects( p11_ctx, sObjects, uMaxObjCnt, &uObjCnt );
    JS_PKCS11_FindObjectsFinal( p11_ctx );

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        JS_PKCS11_GetAtrributeValue2( p11_ctx, sObjects[i], CKA_LABEL, &binLabel );
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
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getSaveFileName( this,
                                                     tr("Wrap Key"),
                                                     QDir::currentPath(),
                                                     tr("BIN Files (*.bin);;All Files (*.*)"),
                                                     &selectedFilter,
                                                     options );

    mPathText->setText( fileName );
}
