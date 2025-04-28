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
#include "hsm_man_dlg.h"

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
    connect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(typeChanged(int)));
    connect( mWrappingMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(wrappingMechChanged(int)));

    connect( mSaveFileBtn, SIGNAL(clicked()), this, SLOT(clickSaveFile()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT( clickClearOutput()));
    connect( mWrapKeyBtn, SIGNAL(clicked()), this, SLOT(clickWrapKey()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(changeOutput()));

    connect( mSelectBtn, SIGNAL(clicked()), this, SLOT(clickSelect()));
    connect( mWrappingSelectBtn, SIGNAL(clicked()), this, SLOT(clickWrappingSelect()));

    mWrappingLabelText->setPlaceholderText( tr( "Select a key from HSM Man" ));
    mLabelText->setPlaceholderText( tr( "Select a key from HSM Man" ));

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
//    mWrappingMechCombo->addItems( kMechWrapSymList );
    mWrappingMechCombo->addItems( sMechWrapSymList );

    const QStringList kTypeList = { "Secret", "Private" };
    mTypeCombo->addItems( kTypeList );
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
        clickWrappingSelect();

        if( mWrappingObjectText->text().length() < 1 )
        {
            manApplet->warningBox( tr( "Select a wrapping object" ), this );
            return;
        }
    }

    if( mObjectText->text().length() < 1 )
    {
        clickSelect();
        if( mObjectText->text().length() < 1 )
        {
            manApplet->warningBox( tr( "Select object" ), this );
            return;
        }
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

void WrapKeyDlg::wrappingTypeChanged( int index )
{
    mWrappingMechCombo->clear();
    mWrappingLabelText->clear();
    mWrappingObjectText->clear();

    if( mWrappingTypeCombo->currentText() == kWrapType.at(0) )
    {
        mWrappingMechCombo->addItems( sMechWrapSymList );
    }
    else
    {
        mWrappingMechCombo->addItems( sMechWrapAsymList );
    }
}

void WrapKeyDlg::typeChanged( int index )
{
    mLabelText->clear();
    mObjectText->clear();
}

void WrapKeyDlg::wrappingMechChanged( int index )
{
    QString strMech = mWrappingMechCombo->currentText();

    if( strMech.length() < 1 )
        mWrappingMechText->clear();
    else
    {
        long uMech = JS_PKCS11_GetCKMType( strMech.toStdString().c_str() );
        mWrappingMechText->setText( QString("0x%1").arg( uMech, 8, 16, QLatin1Char('0')).toUpper());
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

void WrapKeyDlg::clickWrappingSelect()
{
    HsmManDlg hsmMan;
    hsmMan.setSelectedSlot( slot_index_ );
    hsmMan.setTitle( "Select Key" );

    if( mWrappingTypeCombo->currentText().toUpper() == "SECRET" )
        hsmMan.setMode( HsmModeSelectSecretKey, HsmUsageWrap );
    else
    {
        hsmMan.setMode( HsmModeSelectPublicKey, HsmUsageWrap );
        hsmMan.mPublicTypeCombo->setCurrentText( "CKK_RSA" );
    }

    if( hsmMan.exec() == QDialog::Accepted )
    {
        mWrappingLabelText->clear();
        mWrappingObjectText->clear();

        QString strData = hsmMan.getData();
        QStringList listData = strData.split(":");
        if( listData.size() < 3 ) return;

        QString strType = listData.at(0);
        long hObj = listData.at(1).toLong();
        QString strID = listData.at(2);
        QString strLabel = manApplet->cryptokiAPI()->getLabel( session_, hObj );
        mWrappingLabelText->setText( strLabel );
        mWrappingObjectText->setText( QString("%1").arg( hObj ));
    }
}

void WrapKeyDlg::clickSelect()
{
    HsmManDlg hsmMan;
    hsmMan.setSelectedSlot( slot_index_ );
    hsmMan.setTitle( "Select Key" );

    if( mTypeCombo->currentText().toUpper() == "SECRET" )
        hsmMan.setMode( HsmModeSelectSecretKey, HsmUsageWrap );
    else
    {
        hsmMan.setMode( HsmModeSelectPrivateKey, HsmUsageWrap );
    }

    if( hsmMan.exec() == QDialog::Accepted )
    {
        mLabelText->clear();
        mObjectText->clear();

        QString strData = hsmMan.getData();
        QStringList listData = strData.split(":");
        if( listData.size() < 3 ) return;

        QString strType = listData.at(0);
        long hObj = listData.at(1).toLong();
        QString strID = listData.at(2);
        QString strLabel = manApplet->cryptokiAPI()->getLabel( session_, hObj );
        mLabelText->setText( strLabel );
        mObjectText->setText( QString("%1").arg( hObj ));
    }
}
