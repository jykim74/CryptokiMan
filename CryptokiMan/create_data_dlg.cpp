/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "create_data_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"
#include "js_pki_tools.h"

static QStringList sFalseTrue = { "false", "true" };

CreateDataDlg::CreateDataDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    initialize();
    setDefaults();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CreateDataDlg::~CreateDataDlg()
{

}

void CreateDataDlg::setSlotIndex(int index)
{
    slot_index_ = index;
    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    if( index >= 0 )
    {
        slot_info_ = slot_infos.at(slot_index_);
        mSlotNameText->setText( slot_info_.getDesc() );
    }

    mSlotIDText->setText( QString( "%1").arg(slot_info_.getSlotID()));
    mSessionText->setText( QString("%1").arg(slot_info_.getSessionHandle()));
    mLoginText->setText( slot_info_.getLogin() ? "YES" : "NO" );
}


void CreateDataDlg::initialize()
{
    mObjectIDTypeCombo->addItems( kOIDTypeList );
    mLabelText->setPlaceholderText( tr("String value" ));
    mApplicationText->setPlaceholderText( tr("String value" ));
}

void CreateDataDlg::initAttributes()
{
    mDataCombo->addItems( kDataTypeList );

    mPrivateCombo->addItems(sFalseTrue);
    mPrivateCombo->setCurrentIndex(1);

    mModifiableCombo->addItems(sFalseTrue);
    mModifiableCombo->setCurrentIndex(1);

    mCopyableCombo->addItems(sFalseTrue);
    mCopyableCombo->setCurrentIndex(1);

    mDestroyableCombo->addItems(sFalseTrue);
    mDestroyableCombo->setCurrentIndex(1);

    mTokenCombo->addItems(sFalseTrue);
    mTokenCombo->setCurrentIndex(1);
}

void CreateDataDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());

    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void CreateDataDlg::connectAttributes()
{
    connect( mDataCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeData()));
    connect( mDataText, SIGNAL(textChanged()), this, SLOT(changeData()));

    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mCopyableCheck, SIGNAL(clicked()), this, SLOT(clickCopyable()));
    connect( mDestroyableCheck, SIGNAL(clicked()), this, SLOT(clickDestroyable()));

    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mObjectIDTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeObjectID()));
}

void CreateDataDlg::accept()
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

    CK_OBJECT_HANDLE hObject = 0;

    CK_ATTRIBUTE sTemplate[20];
    long        uCount = 0;

    CK_OBJECT_CLASS dataClass = CKO_DATA;

    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &dataClass;
    sTemplate[uCount].ulValueLen = sizeof(dataClass);
    uCount++;

    BIN binLabel = {0,0};

    QString strLabel = mLabelText->text();

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binApplication = {0,0};
    QString strApplication = mApplicationText->text();

    if( !strApplication.isEmpty() )
    {
        JS_BIN_set( &binApplication, (unsigned char *)strApplication.toStdString().c_str(), strApplication.toUtf8().length() );
        sTemplate[uCount].type = CKA_APPLICATION;
        sTemplate[uCount].pValue = binApplication.pVal;
        sTemplate[uCount].ulValueLen = binApplication.nLen;
        uCount++;
    }

    BIN binOID = {0,0};
    QString strOID = mObjectIDText->text();

    if( !strOID.isEmpty() )
    {
//        JS_BIN_decodeHex( strOID.toStdString().c_str(), &binOID );
        QString strType = mObjectIDTypeCombo->currentText();
        QString strValue = mObjectIDText->text();
        getOID( strType, strValue, &binOID );

        sTemplate[uCount].type = CKA_OBJECT_ID;
        sTemplate[uCount].pValue = binOID.pVal;
        sTemplate[uCount].ulValueLen = binOID.nLen;
        uCount++;
    }

    BIN binData = {0,0};
    QString strData = mDataText->toPlainText();

    rv = getBINFromString( &binData, mDataCombo->currentText(), strData );
    if( rv < 0 )
    {
        JS_BIN_reset( &binOID );
        JS_BIN_reset( &binApplication );
        JS_BIN_reset( &binLabel );
        manApplet->formatWarn( rv, this );
        return;
    }

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = binData.pVal;
    sTemplate[uCount].ulValueLen = binData.nLen;
    uCount++;

    if( mModifiableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = ( mModifiableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        sTemplate[uCount].pValue = ( mCopyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = ( mPrivateCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = ( mTokenCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binData );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binApplication );
    JS_BIN_reset( &binOID );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("failed to create data [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("Success to create data"), this );
    manApplet->showTypeList( slot_index_, HM_ITEM_TYPE_DATA );

    QDialog::accept();
}

void CreateDataDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void CreateDataDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void CreateDataDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void CreateDataDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}

void CreateDataDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void CreateDataDlg::changeData()
{
    QString strData = mDataText->toPlainText();
    QString strLen = getDataLenString( mDataCombo->currentText(), strData );
    mDataLenText->setText( QString("%1").arg(strLen));
}

void CreateDataDlg::changeObjectID()
{
    QString strType = mObjectIDTypeCombo->currentText();

    if( strType.toUpper() == "DER HEX" )
        mObjectIDText->setPlaceholderText( tr( "OID DER encoded value" ));
    else if( strType.toUpper() == "VALUE HEX" )
        mObjectIDText->setPlaceholderText( tr("OID value hex") );
    else
        mObjectIDText->setPlaceholderText( tr( "Object identifier" ) );
}

void CreateDataDlg::setDefaults()
{
//    mLabelText->setText( "Data label" );
}
