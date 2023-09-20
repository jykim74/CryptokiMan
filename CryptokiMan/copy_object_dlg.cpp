#include "mainwindow.h"
#include "man_applet.h"
#include "copy_object_dlg.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"
#include "mech_mgr.h"

CopyObjectDlg::CopyObjectDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    session_ = -1;

    setupUi(this);

    initUI();

    connect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeType(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeLabel(int)));

    initAttributes();
    setAttributes();
    connectAttributes();

    initialize();
    setDefaults();

    tabWidget->setCurrentIndex(0);
}

CopyObjectDlg::~CopyObjectDlg()
{

}

void CopyObjectDlg::initUI()
{
    mTypeCombo->addItems( kObjectTypeList );
}

void CopyObjectDlg::slotChanged(int index)
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

void CopyObjectDlg::setSelectedSlot(int index)
{
    slotChanged( index );
}

void CopyObjectDlg::initialize()
{

}

void CopyObjectDlg::initAttributes()
{

}

void CopyObjectDlg::setAttributes()
{

}

void CopyObjectDlg::connectAttributes()
{

}

void CopyObjectDlg::setDefaults()
{

}

void CopyObjectDlg::accept()
{

}

void CopyObjectDlg::changeType( int index )
{
    mLabelCombo->clear();
    QString strType = mTypeCombo->currentText();

    if( strType == "SecretKey" )
        readSecretKeyLabels();
    else if( strType == "PublicKey" )
        readPublicKeyLabels();
    else if( strType == "PrivateKey" )
        readPrivateKeyLabels();
    else if( strType == "Certificate" )
        readCertificateLabels();
    else if( strType == "Data" )
        readDataLabels();
}

void CopyObjectDlg::changeLabel( int index )
{
    QVariant objVal = mLabelCombo->itemData(index);
    mObjectText->setText( QString( "%1" ).arg( objVal.toUInt()));
}

void CopyObjectDlg::readLabels( CK_OBJECT_CLASS objClass )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[10];
    CK_ULONG uCnt = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
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

    int iKeyCnt = mLabelCombo->count();
    if( iKeyCnt > 0 )
    {
        QVariant objVal = mLabelCombo->itemData(0);
        QString strObject = QString("%1").arg( objVal.toInt() );

        mObjectText->setText( strObject );
    }
}

void CopyObjectDlg::readSecretKeyLabels()
{
    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_SECRET_KEY;

    readLabels( objClass );
}

void CopyObjectDlg::readPrivateKeyLabels()
{
    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_PRIVATE_KEY;

    readLabels( objClass );
}

void CopyObjectDlg::readPublicKeyLabels()
{
    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_PUBLIC_KEY;

    readLabels( objClass );
}

void CopyObjectDlg::readCertificateLabels()
{
    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_CERTIFICATE;

    readLabels( objClass );
}

void CopyObjectDlg::readDataLabels()
{
    CK_OBJECT_CLASS objClass = 0;
    objClass = CKO_DATA;

    readLabels( objClass );
}
