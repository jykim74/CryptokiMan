/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "mainwindow.h"
#include "man_applet.h"
#include "copy_object_dlg.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"
#include "mech_mgr.h"
#include "object_view_dlg.h"

static QStringList sFalseTrue = { "false", "true" };

CopyObjectDlg::CopyObjectDlg(QWidget *parent) :
    QDialog(parent)
{
    is_fix_ = false;

    setupUi(this);

    initUI();

    connect( mObjectViewBtn, SIGNAL(clicked()), this, SLOT(clickObjectView()));
    connect( mSrcTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeSrcType(int)));
    connect( mSrcLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeSrcLabel(int)));

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

CopyObjectDlg::~CopyObjectDlg()
{

}

void CopyObjectDlg::initUI()
{
    mSrcTypeCombo->addItems( kObjectTypeList );
}

void CopyObjectDlg::setSlotIndex(int index)
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

    changeSrcType(0);
}

void CopyObjectDlg::setTypeObject( int nType, const QString strLabel, long hObj )
{
    is_fix_ = true;

    mSrcTypeCombo->clear();
    mSrcLabelCombo->clear();
    mSrcObjectText->clear();

    QVariant objVal = QVariant( (int)hObj );

    if( nType == HM_ITEM_TYPE_DATA )
        mSrcTypeCombo->addItem( kData );
    else if( nType == HM_ITEM_TYPE_CERTIFICATE )
        mSrcTypeCombo->addItem( kCertificate );
    else if( nType == HM_ITEM_TYPE_PUBLICKEY )
        mSrcTypeCombo->addItem( kPublicKey );
    else if( nType == HM_ITEM_TYPE_PRIVATEKEY )
        mSrcTypeCombo->addItem( kPrivateKey );
    else if( nType == HM_ITEM_TYPE_SECRETKEY )
        mSrcTypeCombo->addItem( kSecretKey );

    mSrcLabelCombo->addItem( strLabel, objVal );
    mSrcObjectText->setText( QString("%1").arg( hObj));
}

void CopyObjectDlg::initialize()
{

}

void CopyObjectDlg::initAttributes()
{
    mPrivateCombo->addItems(sFalseTrue);
    mPrivateCombo->setCurrentIndex(1);

    mModifiableCombo->addItems(sFalseTrue);
    mModifiableCombo->setCurrentIndex(1);

    mDestroyableCombo->addItems(sFalseTrue);
    mDestroyableCombo->setCurrentIndex(1);

    mTokenCombo->addItems(sFalseTrue);
    mTokenCombo->setCurrentIndex(1);
}

void CopyObjectDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void CopyObjectDlg::connectAttributes()
{
    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mDestroyableCheck, SIGNAL(clicked()), this, SLOT(clickDestroyable()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
}

void CopyObjectDlg::setDefaults()
{
    /*
    mPrivateCheck->setChecked(true);
    mPrivateCombo->setEnabled(true);
    mPrivateCombo->setCurrentIndex(1);

    mTokenCheck->setChecked(true);
    mTokenCombo->setEnabled(true);
    mTokenCombo->setCurrentIndex(1);
    */
}

void CopyObjectDlg::clickObjectView()
{
    long hObject = mSrcObjectText->text().toLong();
    if( hObject <= 0 )
    {
        manApplet->warningBox( tr("There is no object" ), this );
        return;
    }

    ObjectViewDlg objectView;
    objectView.setSlotIndex(slot_index_);
    objectView.setObject( hObject );
    objectView.exec();
}

void CopyObjectDlg::accept()
{
    int rv = -1;

    QString strSrcObject = mSrcObjectText->text();

    if( strSrcObject.toInt() <= 0  )
    {
        QMessageBox::warning( this, "Copy Object", tr("There is no handler for the source.") );
        return;
    }

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE uNewObj = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;


    if( mPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = ( mPrivateCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mModifiableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = ( mModifiableCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = ( mTokenCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CopyObject( slot_info_.getSessionHandle(), strSrcObject.toLong(), sTemplate, uCount, &uNewObj );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "CopyObject execution failed [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    QString strNewObject = QString("%1").arg( uNewObj );
    QString strSrcType = mSrcTypeCombo->currentText();
    int nDataType = -1;


    if( strSrcType == kCertificate )
        nDataType = HM_ITEM_TYPE_CERTIFICATE;
    else if( strSrcType == kPublicKey )
        nDataType = HM_ITEM_TYPE_PUBLICKEY;
    else if( strSrcType == kPrivateKey )
        nDataType = HM_ITEM_TYPE_PRIVATEKEY;
    else if( strSrcType == kSecretKey )
        nDataType = HM_ITEM_TYPE_SECRETKEY;
    else if( strSrcType == kData )
        nDataType = HM_ITEM_TYPE_DATA;

    manApplet->clickTreeMenu( slot_index_, nDataType );
    manApplet->messageBox( tr("CopyObject successful [New Object Handle: %1]").arg( strNewObject), this );


    QDialog::accept();
}

void CopyObjectDlg::changeSrcType( int index )
{
    mSrcLabelCombo->clear();
    QString strType = mSrcTypeCombo->currentText();

    if( strType == "SecretKey" )
        readSrcSecretKeyLabels();
    else if( strType == "PublicKey" )
        readSrcPublicKeyLabels();
    else if( strType == "PrivateKey" )
        readSrcPrivateKeyLabels();
    else if( strType == "Certificate" )
        readSrcCertificateLabels();
    else if( strType == "Data" )
        readSrcDataLabels();
}

void CopyObjectDlg::changeSrcLabel( int index )
{
    QVariant objVal = mSrcLabelCombo->itemData(index);
    mSrcObjectText->setText( QString( "%1" ).arg( objVal.toUInt()));
}

void CopyObjectDlg::readSrcLabels( CK_OBJECT_CLASS objClass )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[10];
    CK_ULONG uCnt = 0;
    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE sObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

//    CK_OBJECT_CLASS objClass = 0;
//    objClass = CKO_SECRET_KEY;

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_COPYABLE;
    sTemplate[uCnt].pValue = &kTrue;
    sTemplate[uCnt].ulValueLen = sizeof(CK_BBOOL);
    uCnt++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( slot_info_.getSessionHandle(), sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( slot_info_.getSessionHandle(), sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( slot_info_.getSessionHandle() );
    if( rv != CKR_OK ) return;

    mSrcLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;

        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( slot_info_.getSessionHandle(), sObjects[i], CKA_LABEL, &binLabel );

        JS_BIN_string( &binLabel, &pLabel );

        mSrcLabelCombo->addItem( pLabel, objVal );

        if( pLabel ) JS_free( pLabel );
        JS_BIN_reset( &binLabel );
    }

    int iKeyCnt = mSrcLabelCombo->count();
    if( iKeyCnt > 0 )
    {
        QVariant objVal = mSrcLabelCombo->itemData(0);
        QString strObject = QString("%1").arg( objVal.toInt() );

        mSrcObjectText->setText( strObject );
    }
    else
    {
        mSrcObjectText->clear();
    }
}

void CopyObjectDlg::readSrcSecretKeyLabels()
{
    if( is_fix_ == true ) return;

    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_SECRET_KEY;

    readSrcLabels( objClass );
}

void CopyObjectDlg::readSrcPrivateKeyLabels()
{
    if( is_fix_ == true ) return;

    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_PRIVATE_KEY;

    readSrcLabels( objClass );
}

void CopyObjectDlg::readSrcPublicKeyLabels()
{
    if( is_fix_ == true ) return;

    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_PUBLIC_KEY;

    readSrcLabels( objClass );
}

void CopyObjectDlg::readSrcCertificateLabels()
{
    if( is_fix_ == true ) return;

    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_CERTIFICATE;

    readSrcLabels( objClass );
}

void CopyObjectDlg::readSrcDataLabels()
{
    if( is_fix_ == true ) return;

    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_DATA;

    readSrcLabels( objClass );
}

void CopyObjectDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void CopyObjectDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void CopyObjectDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}

void CopyObjectDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

