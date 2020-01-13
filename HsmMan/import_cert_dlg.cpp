#include <QFileDialog>

#include "import_cert_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

static QStringList sFalseTrue = { "false", "true" };

ImportCertDlg::ImportCertDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT( slotChanged(int) ));
}

ImportCertDlg::~ImportCertDlg()
{

}

void ImportCertDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void ImportCertDlg::showEvent(QShowEvent* event )
{
    initialize();
    setDefaults();
}

void ImportCertDlg::initialize()
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

void ImportCertDlg::initAttributes()
{
    mPrivateCombo->addItems(sFalseTrue);
    mSensitiveCombo->addItems(sFalseTrue);
    mModifiableCombo->addItems(sFalseTrue);
    mTokenCombo->addItems(sFalseTrue);
}

void ImportCertDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void ImportCertDlg::connectAttributes()
{
    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickSensitive()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));
}

void ImportCertDlg::accept()
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE   hSession = slotInfo.getSessionHandle();

    QString strCertPath = mCertPathText->text();

    if( strCertPath.isEmpty() )
    {
        manApplet->warningBox( tr("You have to select certificate file."), this );
        return;
    }

    BIN binCert = {0,0};
    JS_BIN_fileRead( strCertPath.toStdString().c_str(), &binCert );

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = 0;
    CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = binCert.pVal;
    sTemplate[uCount].ulValueLen = binCert.nLen;
    uCount++;

    QString strLabel = mLabelText->text();
    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_decodeHex( strLabel.toStdString().c_str(), &binLabel );

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mIDText->text();
    BIN binID = {0,0};

    if( !strID.isEmpty() )
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

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
        manApplet->warningBox( tr("fail to create certificate(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox(tr("success to create certificate"), this );
    QDialog::accept();
}

void ImportCertDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void ImportCertDlg::clickSensitive()
{
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
}

void ImportCertDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void ImportCertDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void ImportCertDlg::clickFind()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("QFileDialog::getOpenFileName()"),
                                                     "D:/test",
                                                     tr("DLL Files (*.dll);;All Files (*.*)"),
                                                     &selectedFilter,
                                                     options );

    mCertPathText->setText( fileName );
}

void ImportCertDlg::setDefaults()
{
    mLabelText->setText( "certificate label" );
    mIDText->setText( "certificate ID" );

    mTokenCheck->setChecked(true);
    mTokenCombo->setEnabled(true);
    mTokenCombo->setCurrentIndex(1);
}
