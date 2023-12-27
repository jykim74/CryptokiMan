#include "create_data_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"
#include "js_pki_tools.h"

static QStringList sFalseTrue = { "false", "true" };
static QStringList sDataList = { "String", "Hex", "Base64" };
static QStringList sOIDTypeList = { "Text", "Value Hex", "ShortName", "LongName", "DER Hex" };

CreateDataDlg::CreateDataDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));

    initialize();
    setDefaults();
}

CreateDataDlg::~CreateDataDlg()
{

}

void CreateDataDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void CreateDataDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}


void CreateDataDlg::initialize()
{
    mSlotsCombo->clear();
    mObjectIDTypeCombo->addItems( sOIDTypeList );

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    for( int i=0; i < slot_infos.size(); i++ )
    {
        SlotInfo slotInfo = slot_infos.at(i);

        mSlotsCombo->addItem( slotInfo.getDesc() );
    }

    if( slot_infos.size() > 0 ) slotChanged(0);
}

void CreateDataDlg::initAttributes()
{
    mDataCombo->addItems(sDataList);

    mPrivateCombo->addItems(sFalseTrue);
    mModifiableCombo->addItems(sFalseTrue);
    mCopyableCombo->addItems(sFalseTrue);
    mDestroyableCombo->addItems(sFalseTrue);

    mTokenCombo->addItems(sFalseTrue);
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
    connect( mDataText, SIGNAL(textChanged()), this, SLOT(changeData()));

    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mCopyableCheck, SIGNAL(clicked()), this, SLOT(clickCopyable()));
    connect( mDestroyableCheck, SIGNAL(clicked()), this, SLOT(clickDestroyable()));

    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
}

void CreateDataDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binApplication = {0,0};
    QString strApplication = mApplicationText->text();

    if( !strApplication.isEmpty() )
    {
        JS_BIN_set( &binApplication, (unsigned char *)strApplication.toStdString().c_str(), strApplication.length() );
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
        getOID( &binOID );
        sTemplate[uCount].type = CKA_OBJECT_ID;
        sTemplate[uCount].pValue = binOID.pVal;
        sTemplate[uCount].ulValueLen = binOID.nLen;
        uCount++;
    }

    BIN binData = {0,0};
    QString strData = mDataText->toPlainText();

    if( mDataCombo->currentIndex() == 0 )
        JS_BIN_set( &binData, (unsigned char *)strData.toStdString().c_str(), strData.length() );
    else if( mDataCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );
    else if( mDataCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strData.toStdString().c_str(), &binData );

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
        manApplet->warningBox( tr("fail to create data(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("Success to create data"), this );
    manApplet->showTypeList( index, HM_ITEM_TYPE_DATA );

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
    int nLen = getDataLen( mDataCombo->currentText(), strData );
    mDataLenText->setText( QString("%1").arg(nLen));
}

void CreateDataDlg::setDefaults()
{
    mLabelText->setText( "Data label" );

    mPrivateCheck->setChecked(true);
    mPrivateCombo->setEnabled(true);
    mPrivateCombo->setCurrentIndex(1);

    mTokenCheck->click();
    mTokenCombo->setCurrentIndex(1);
}

void CreateDataDlg::getOID( BIN *pOID )
{
    // { "Text", "Value Hex", "ShortName", "LongName", "DER Hex" };
    QString strType = mObjectIDTypeCombo->currentText();
    QString strValue = mObjectIDText->text();

    BIN binVal = {0,0};
    char sOIDText[128];

    memset( sOIDText, 0x00, sizeof(sOIDText));

    if( strValue.length() <= 0 ) return;

    if( strType == "Text" )
    {
        JS_PKI_getOIDFromString( strValue.toStdString().c_str(), pOID );
    }
    else if( strType == "Value Hex" )
    {
        JS_BIN_decodeHex( strValue.toStdString().c_str(), &binVal );
        JS_PKI_getStringFromOIDValue( &binVal, sOIDText );
        JS_PKI_getOIDFromString( sOIDText, pOID );
        JS_BIN_reset( &binVal );
    }
    else if( strType == "ShortName" )
    {
        JS_PKI_getOIDFromSN( strValue.toStdString().c_str(), sOIDText );
        JS_PKI_getOIDFromString( sOIDText, pOID );
    }
    else if( strType == "LongName" )
    {
        JS_PKI_getOIDFromLN( strValue.toStdString().c_str(), sOIDText );
        JS_PKI_getOIDFromString( sOIDText, pOID );
    }
    else
    {
        JS_BIN_decodeHex( strValue.toStdString().c_str(), pOID );
    }

    JS_BIN_reset( &binVal );
}
