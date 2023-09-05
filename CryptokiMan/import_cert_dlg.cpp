#include <QFileDialog>

#include "import_cert_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "common.h"
#include "cryptoki_api.h"

static QStringList sFalseTrue = { "false", "true" };

ImportCertDlg::ImportCertDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT( slotChanged(int) ));
    initialize();
    setDefaults();

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

void ImportCertDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
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

    mSubjectInCertCheck->setChecked( true );
    clickSubjectInCertCheck();
}

void ImportCertDlg::initAttributes()
{
    mPrivateCombo->addItems(sFalseTrue);
    mSensitiveCombo->addItems(sFalseTrue);
    mModifiableCombo->addItems(sFalseTrue);
    mTokenCombo->addItems(sFalseTrue);

    QDate nowDate = QDate::currentDate();
    mStartDateEdit->setDate(nowDate);
    mEndDateEdit->setDate(nowDate);
}

void ImportCertDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());

}

void ImportCertDlg::connectAttributes()
{
    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickSensitive()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));
    connect( mStartDateCheck, SIGNAL(clicked()), this, SLOT(clickStartDate()));
    connect( mEndDateCheck, SIGNAL(clicked()), this, SLOT(clickEndDate()));

    connect( mSubjectInCertCheck, SIGNAL(clicked()), this, SLOT(clickSubjectInCertCheck()));
}

void ImportCertDlg::accept()
{
    int ret = 0;

    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    QString strCertPath = mCertPathText->text();
    QString strSubject;

    if( strCertPath.isEmpty() )
    {
        manApplet->warningBox( tr("You have to select certificate file."), this );
        return;
    }

    BIN binCert = {0,0};
    BIN binSubject = {0,0};

    if( mSubjectInCertCheck->isChecked() )
    {
        JCertInfo sCertInfo;
        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );

        ret = JS_PKI_getCertSubjetDN( &binCert, &binSubject );
        if( ret != 0 )
        {
            manApplet->elog( QString( "fail to decode certificate: %1" ).arg(ret) );
            JS_BIN_reset( &binCert );
            return;
        }
    }
    else
    {
        JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );
    }

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = 0;
    CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_CERTIFICATE_TYPE;
    sTemplate[uCount].pValue = &certType;
    sTemplate[uCount].ulValueLen = sizeof(certType);
    uCount++;

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = binCert.pVal;
    sTemplate[uCount].ulValueLen = binCert.nLen;
    uCount++;

    QString strLabel = mLabelText->text();
    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.length() );

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

//    if( !strSubject.isEmpty() )
    if( binSubject.nLen > 0 )
    {
//        JS_BIN_set( &binSubject, (unsigned char *)strSubject.toStdString().c_str(), strSubject.length() );
        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
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

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binSubject );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create certificate(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox(tr("success to create certificate"), this );
    manApplet->showTypeList( index, HM_ITEM_TYPE_CERTIFICATE );

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

void ImportCertDlg::clickStartDate()
{
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
}

void ImportCertDlg::clickEndDate()
{
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());
}


void ImportCertDlg::clickFind()
{  
    QString strPath = manApplet->curFile();

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mCertPathText->setText( fileName );
    manApplet->setCurFile( fileName );
}

void ImportCertDlg::clickSubjectInCertCheck()
{
    bool bVal = mSubjectInCertCheck->isChecked();

    mSubjectText->setEnabled( !bVal );
}

void ImportCertDlg::setDefaults()
{
    mLabelText->setText( "certificate label" );
    mIDText->setText( "01020304" );

    mTokenCheck->setChecked(true);
    mTokenCombo->setEnabled(true);
    mTokenCombo->setCurrentIndex(1);

    QDateTime nowTime;
    nowTime.setTime_t( time(NULL) );

    mStartDateEdit->setDate( nowTime.date() );
    mEndDateEdit->setDate( nowTime.date() );
}
