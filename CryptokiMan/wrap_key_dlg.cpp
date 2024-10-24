/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>

#include "wrap_key_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"
#include "mech_mgr.h"

static QStringList sMechWrapSymList;
static QStringList sMechWrapAsymList;


WrapKeyDlg::WrapKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    session_ = -1;

    setupUi(this);

    connect( mWrappingParamText, SIGNAL(textChanged(const QString&)), this, SLOT(changeWrappingParam(const QString&)));

    initUI();
    mWrapKeyBtn->setDefault( true );

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

WrapKeyDlg::~WrapKeyDlg()
{

}

void WrapKeyDlg::initUI()
{
    connect( mWrappingTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(wrappingTypeChanged(int)));
    connect( mWrappingLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(wrappingLabelChanged(int)));
    connect( mWrappingMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(wrappingMechChanged(int)));

    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));
    connect( mSaveFileBtn, SIGNAL(clicked()), this, SLOT(clickSaveFile()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT( clickClearOutput()));
    connect( mWrapKeyBtn, SIGNAL(clicked()), this, SLOT(clickWrapKey()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(changeOutput()));

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

//    setWrapLabelList();
    wrappingTypeChanged(0);
    setLabelKeyList();
}

void WrapKeyDlg::initialize()
{
    /* kMechWrapSymList 와 kMechWrapAsymList 는 라이선스와 상관없이 동일 함 */

    if( manApplet->isLicense() == true && manApplet->settingsMgr()->useDeviceMech() == true )
    {
        sMechWrapSymList = manApplet->mechMgr()->getWrapList( MECH_TYPE_SYM );
        sMechWrapAsymList = manApplet->mechMgr()->getWrapList( MECH_TYPE_ASYM );
    }
    else
    {
        sMechWrapSymList = kMechWrapSymList;
        sMechWrapAsymList = kMechWrapAsymList;
    }

    mWrappingTypeCombo->addItems( kWrapType );
    mWrappingMechCombo->addItems( kMechWrapSymList );
}

void WrapKeyDlg::clickWrapKey()
{
    int rv = -1;

    long hWrappingKey = mWrappingObjectText->text().toLong();
    long hKey = mObjectText->text().toLong();

    CK_MECHANISM sMech;

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = JS_PKCS11_GetCKMType( mWrappingMechCombo->currentText().toStdString().c_str());

    if( mWrappingObjectText->text().length() < 1 )
    {
        manApplet->warningBox( tr( "Select a wrapping object" ), this );
        mWrappingLabelCombo->setFocus();
        return;
    }

    if( mObjectText->text().length() < 1 )
    {
        manApplet->warningBox( tr( "Select object" ), this );
        mLabelCombo->setFocus();
        return;
    }

    QString strParam = mWrappingParamText->text();
    BIN binParam = {0,0};

    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );
        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }

    CK_BYTE_PTR pData = NULL;
    CK_ULONG uDataLen = 0;

    rv = manApplet->cryptokiAPI()->WrapKey( session_, &sMech, hWrappingKey, hKey, pData, &uDataLen );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("WrapKey execution failure [%1]").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    pData = (CK_BYTE_PTR)JS_malloc( uDataLen );
    if( pData == NULL ) return;

    rv = manApplet->cryptokiAPI()->WrapKey( session_, &sMech, hWrappingKey, hKey, pData, &uDataLen );

    JS_BIN_reset( &binParam );

    if( rv != CKR_OK )
    {
        if( pData ) JS_free( pData );
        manApplet->warningBox( tr("WrapKey execution failure [%1]").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    BIN binWrapped = {0,0};
    JS_BIN_set( &binWrapped, pData, uDataLen );
    mOutputText->setPlainText( getHexString( binWrapped.pVal, binWrapped.nLen));


    if( pData ) JS_free( pData );
    JS_BIN_reset( &binWrapped );

    manApplet->messageLog( "WrapKey execution successful", this );
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

void WrapKeyDlg::wrappingTypeChanged( int index )
{
    mWrappingMechCombo->clear();

    if( mWrappingTypeCombo->currentText() == kWrapType.at(0) )
    {
        mWrappingMechCombo->addItems( sMechWrapSymList );
        setWrappingSecretLabel();
    }
    else
    {
        mWrappingMechCombo->addItems( sMechWrapAsymList );
        setWrappingRSAPublicLabel();
    }
}

void WrapKeyDlg::wrappingMechChanged( int index )
{
    QString strMech = mWrappingMechCombo->currentText();

    if( strMech.length() < 1 )
        mWrappingMechText->clear();
    else
    {
        long uMech = JS_PKCS11_GetCKMType( strMech.toStdString().c_str() );
        mWrappingMechText->setText( QString("%1").arg( uMech, 8, 16, QLatin1Char('0')));
    }
}

void WrapKeyDlg::clickSaveFile()
{
    BIN binOut = {0,0};
    QString strOutput = mOutputText->toPlainText();
    QString strPath = manApplet->curFilePath();

    if( strOutput.length() < 1 )
    {
        manApplet->warningBox( tr( "No result data"), this );
        return;
    }

    getBINFromString( &binOut, DATA_HEX, strOutput );

    QString fileName = findSaveFile( this, JS_FILE_TYPE_BIN, strPath );
    if( fileName.isEmpty() )
    {
        JS_BIN_reset( &binOut );
        return;
    }

    JS_BIN_fileWrite( &binOut, fileName.toLocal8Bit().toStdString().c_str() );
    JS_BIN_reset( &binOut );
}

void WrapKeyDlg::clickClearOutput()
{
    mOutputText->clear();
}

void WrapKeyDlg::changeOutput()
{
    QString strOut = mOutputText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strOut );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void WrapKeyDlg::changeWrappingParam(const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mWrappingParamLenText->setText( QString("%1").arg(strLen));
}

void WrapKeyDlg::setWrappingSecretLabel()
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[10];
    CK_ULONG uCnt = 0;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE sObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;

    objClass = CKO_SECRET_KEY;

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_WRAP;
    sTemplate[uCnt].pValue = &kTrue;
    sTemplate[uCnt].ulValueLen = sizeof(CK_BBOOL);
    uCnt++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
    if( rv != CKR_OK ) return;

    mWrappingLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;

        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

        JS_BIN_string( &binLabel, &pLabel );

        mWrappingLabelCombo->addItem( pLabel, objVal );

        if( pLabel ) JS_free( pLabel );
        JS_BIN_reset( &binLabel );
    }

    int iKeyCnt = mWrappingLabelCombo->count();
    if( iKeyCnt > 0 )
    {
        QVariant objVal = mWrappingLabelCombo->itemData(0);
        QString strObject = QString("%1").arg( objVal.toInt() );

        mWrappingObjectText->setText( strObject );
    }
}

void WrapKeyDlg::setWrappingRSAPublicLabel()
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[10];
    CK_ULONG uCnt = 0;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE sObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_KEY_TYPE;
    sTemplate[uCnt].pValue = &keyType;
    sTemplate[uCnt].ulValueLen = sizeof(keyType);
    uCnt++;

    sTemplate[uCnt].type = CKA_WRAP;
    sTemplate[uCnt].pValue = &kTrue;
    sTemplate[uCnt].ulValueLen = sizeof(CK_BBOOL);
    uCnt++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
    if( rv != CKR_OK ) return;

    mWrappingLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;

        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

        JS_BIN_string( &binLabel, &pLabel );

        mWrappingLabelCombo->addItem( pLabel, objVal );

        if( pLabel ) JS_free( pLabel );
        JS_BIN_reset( &binLabel );
    }

    int iKeyCnt = mWrappingLabelCombo->count();
    if( iKeyCnt > 0 )
    {
        QVariant objVal = mWrappingLabelCombo->itemData(0);
        QString strObject = QString("%1").arg( objVal.toInt() );

        mWrappingObjectText->setText( strObject );
    }
}

void WrapKeyDlg::setLabelKeyList()
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[10];
    CK_ULONG uCnt = 0;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE sObjects[uMaxObjCnt];
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

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;

        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

        JS_BIN_string( &binLabel, &pLabel );

        mLabelCombo->addItem( pLabel, objVal );

        if( pLabel ) JS_free( pLabel );
        JS_BIN_reset( &binLabel );
    }

    uCnt = 0;
    uObjCnt = 0;
    objClass = CKO_PRIVATE_KEY;
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

        if( pLabel ) JS_free( pLabel );
        JS_BIN_reset( &binLabel );
    }

    int iKeyCnt = mLabelCombo->count();
    if( iKeyCnt > 0 )
    {
        QVariant objVal = mLabelCombo->itemData(0);
        QString strObject = QString("%1").arg( objVal.toInt() );

        mObjectText->setText( strObject );
    }
}
