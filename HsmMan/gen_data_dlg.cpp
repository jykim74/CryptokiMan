#include "gen_data_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

static QStringList sFalseTrue = { "false", "true" };

static QStringList sDataList = { "String", "Hex", "Base64" };

GenDataDlg::GenDataDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();
}

GenDataDlg::~GenDataDlg()
{

}

void GenDataDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void GenDataDlg::showEvent(QShowEvent* event )
{
    initialize();
}

void GenDataDlg::initialize()
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

void GenDataDlg::initAttributes()
{
    mDataCombo->addItems(sDataList);

    mPrivateCombo->addItems(sFalseTrue);
    mSensitiveCombo->addItems(sFalseTrue);
    mModifiableCombo->addItems(sFalseTrue);
    mTokenCombo->addItems(sFalseTrue);
}

void GenDataDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void GenDataDlg::connectAttributes()
{
    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickSensitive()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
}

void GenDataDlg::accept()
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(index);
    int rv = -1;

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

    BIN binData = {0,0};
    QString strData = mDataText->text();

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

    if( mPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = ( mPrivateCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mSensitiveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SENSITIVE;
        sTemplate[uCount].pValue = ( mSensitiveCombo->currentIndex() ? &bTrue : &bFalse );
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

    rv = JS_PKCS11_CreateObject( p11_ctx, hSession, sTemplate, uCount, &hObject );
    if( rv != CKR_OK )
    {
        return;
    }

    QDialog::accept();
}

void GenDataDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void GenDataDlg::clickSensitive()
{
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
}

void GenDataDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void GenDataDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}
