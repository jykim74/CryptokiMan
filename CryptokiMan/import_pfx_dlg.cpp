#include <QFileDialog>

#include "import_pfx_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "common.h"
#include "cryptoki_api.h"

static QStringList sFalseTrue = { "false", "true" };

ImportPFXDlg::ImportPFXDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT( slotChanged(int) ));
    initialize();
    setDefaults();

    tabWidget->setCurrentIndex(0);
    subject_in_cert_ = "";
}

ImportPFXDlg::~ImportPFXDlg()
{

}

void ImportPFXDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void ImportPFXDlg::initialize()
{
    mSlotsCombo->clear();

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    for( int i=0; i < slot_infos.size(); i++ )
    {
        SlotInfo slotInfo = slot_infos.at(i);

        mSlotsCombo->addItem( slotInfo.getDesc() );
    }

    if( slot_infos.size() > 0 ) slotChanged(0);

    mCertSubjectInCertCheck->setChecked( true );
    mPriSubjectInCertCheck->setChecked( true );

    clickCertSubjectInCertCheck();
    clickPriSubjectInCertCheck();
}

void ImportPFXDlg::initAttributes()
{
    mPriPrivateCombo->addItems( sFalseTrue );
    mPriDecryptCombo->addItems( sFalseTrue );
    mPriSignCombo->addItems( sFalseTrue );
    mPriUnwrapCombo->addItems( sFalseTrue );
    mPriModifiableCombo->addItems( sFalseTrue );
    mPriSensitiveCombo->addItems( sFalseTrue );
    mPriDeriveCombo->addItems( sFalseTrue );
    mPriExtractableCombo->addItems( sFalseTrue );
    mPriTokenCombo->addItems( sFalseTrue );

    mPubPrivateCombo->addItems( sFalseTrue );
    mPubEncryptCombo->addItems( sFalseTrue );
    mPubWrapCombo->addItems( sFalseTrue );
    mPubVerifyCombo->addItems( sFalseTrue );
    mPubDeriveCombo->addItems( sFalseTrue );
    mPubModifiableCombo->addItems( sFalseTrue );
    mPubTokenCombo->addItems( sFalseTrue );

    mCertPrivateCombo->addItems( sFalseTrue );
    mCertSensitiveCombo->addItems( sFalseTrue );
    mCertModifiableCombo->addItems( sFalseTrue );
    mCertTokenCombo->addItems( sFalseTrue );

    QDate nowDate = QDate::currentDate();
    mPubStartDateEdit->setDate(nowDate);
    mPubEndDateEdit->setDate(nowDate);
    mPriStartDateEdit->setDate(nowDate);
    mPriEndDateEdit->setDate(nowDate);
}

void ImportPFXDlg::setAttributes()
{
    mPriPrivateCombo->setEnabled( mPriPrivateCheck->isChecked() );
    mPriDecryptCombo->setEnabled( mPriDecryptCheck->isChecked() );
    mPriSignCombo->setEnabled( mPriSignCheck->isChecked() );
    mPriUnwrapCombo->setEnabled( mPriUnwrapCheck->isChecked() );
    mPriModifiableCombo->setEnabled( mPriModifiableCheck->isChecked() );
    mPriSensitiveCombo->setEnabled( mPriSensitiveCheck->isChecked() );
    mPriDeriveCombo->setEnabled( mPriDeriveCheck->isChecked() );
    mPriExtractableCombo->setEnabled( mPriExtractableCheck->isChecked() );
    mPriTokenCombo->setEnabled( mPriTokenCheck->isChecked() );
    mPriStartDateEdit->setEnabled( mPriStartDateCheck->isChecked() );
    mPriEndDateEdit->setEnabled( mPriEndDateCheck->isChecked() );

    mPubPrivateCombo->setEnabled( mPubPrivateCheck->isChecked() );
    mPubEncryptCombo->setEnabled( mPubEncryptCheck->isChecked() );
    mPubWrapCombo->setEnabled( mPubWrapCheck->isChecked() );
    mPubVerifyCombo->setEnabled( mPubVerifyCheck->isChecked() );
    mPubDeriveCombo->setEnabled( mPubDeriveCheck->isChecked() );
    mPubModifiableCombo->setEnabled( mPubModifiableCheck->isChecked() );
    mPubTokenCombo->setEnabled( mPubTokenCheck->isChecked() );
    mPubStartDateEdit->setEnabled( mPubStartDateCheck->isChecked() );
    mPubEndDateEdit->setEnabled( mPubEndDateCheck->isChecked() );

    mCertPrivateCombo->setEnabled(mCertPrivateCheck->isChecked());
    mCertSensitiveCombo->setEnabled(mCertSensitiveCheck->isChecked());
    mCertModifiableCombo->setEnabled(mCertModifiableCheck->isChecked());
    mCertTokenCombo->setEnabled(mCertTokenCheck->isChecked());
    mCertStartDateEdit->setEnabled( mCertStartDateCheck->isChecked() );
    mCertEndDateEdit->setEnabled( mCertEndDateCheck->isChecked() );
}

void ImportPFXDlg::connectAttributes()
{
    connect( mPriPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPriPrivate()));
    connect( mPriDecryptCheck, SIGNAL(clicked()), this, SLOT(clickPriDecrypt()));
    connect( mPriSignCheck, SIGNAL(clicked()), this, SLOT(clickPriSign()));
    connect( mPriUnwrapCheck, SIGNAL(clicked()), this, SLOT(clickPriUnwrap()));
    connect( mPriModifiableCheck, SIGNAL(clicked()), this, SLOT(clickPriModifiable()));
    connect( mPriSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickPriSensitive()));
    connect( mPriDeriveCheck, SIGNAL(clicked()), this, SLOT(clickPriDerive()));
    connect( mPriExtractableCheck, SIGNAL(clicked()), this, SLOT(clickPriExtractable()));
    connect( mPriTokenCheck, SIGNAL(clicked()), this, SLOT(clickPriToken()));
    connect( mPriStartDateCheck, SIGNAL(clicked()), this, SLOT(clickPriStartDate()));
    connect( mPriEndDateCheck, SIGNAL(clicked()), this, SLOT(clickPriEndDate()));

    connect( mPubPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPubPrivate()));
    connect( mPubEncryptCheck, SIGNAL(clicked()), this, SLOT(clickPubEncrypt()));
    connect( mPubWrapCheck, SIGNAL(clicked()), this, SLOT(clickPubWrap()));
    connect( mPubVerifyCheck, SIGNAL(clicked()), this, SLOT(clickPubVerify()));
    connect( mPubDeriveCheck, SIGNAL(clicked()), this, SLOT(clickPubDerive()));
    connect( mPubModifiableCheck, SIGNAL(clicked()), this, SLOT(clickPubModifiable()));
    connect( mPubTokenCheck, SIGNAL(clicked()), this, SLOT(clickPubToken()));
    connect( mPubStartDateCheck, SIGNAL(clicked()), this, SLOT(clickPubStartDate()));
    connect( mPubEndDateCheck, SIGNAL(clicked()), this, SLOT(clickPubEndDate()));

    connect( mCertPrivateCheck, SIGNAL(clicked()), this, SLOT(clickCertPrivate()));
    connect( mCertSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickCertSensitive()));
    connect( mCertModifiableCheck, SIGNAL(clicked()), this, SLOT(clickCertModifiable()));
    connect( mCertTokenCheck, SIGNAL(clicked()), this, SLOT(clickCertToken()));
    connect( mCertStartDateCheck, SIGNAL(clicked()), this, SLOT(clickCertStartDate()));
    connect( mCertEndDateCheck, SIGNAL(clicked()), this, SLOT(clickCertEndDate()));

    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));
    connect( mCertSubjectInCertCheck, SIGNAL(clicked()), this, SLOT(clickCertSubjectInCertCheck()));
    connect( mPriSubjectInCertCheck, SIGNAL(clicked()), this, SLOT(clickPriSubjectInCertCheck()));
}

void ImportPFXDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;

    QString strPFXPath = mPFXPathText->text();
    BIN binPFX = {0,0};

    if( strPFXPath.isEmpty() )
    {
        manApplet->warningBox( tr("You have to select pfx file."), this );
        return;
    }

    JS_BIN_fileReadBER( strPFXPath.toLocal8Bit().toStdString().c_str(), &binPFX );

    QString strPasswd = mPasswordText->text();
    if( strPasswd.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert password."), this );
        mPasswordText->setFocus();;
        return;
    }

    BIN binPri = {0,0};
    BIN binCert = {0,0};
    JRSAKeyVal rsaKeyVal;
    JECKeyVal ecKeyVal;
    JCertInfo sCertInfo;

    memset( &rsaKeyVal, 0x00, sizeof(JRSAKeyVal));
    memset( &ecKeyVal, 0x00, sizeof(JECKeyVal));
    memset( &sCertInfo, 0x00, sizeof(sCertInfo));


    rv = JS_PKI_decodePFX( &binPFX, strPasswd.toStdString().c_str(), &binPri, &binCert );
    if( rv != 0 )
    {
        manApplet->warningBox( tr( "fail to decode PFX"), this );
        return;
    }

    rv = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
    if( rv == 0 )
    {
        subject_in_cert_ = sCertInfo.pSubjectName;
    }

    rv = createCert( &binCert );

    rv = JS_PKI_getRSAKeyVal( &binPri, &rsaKeyVal );
    if( rv == 0 )
    {
        createRSAPrivateKey( &rsaKeyVal );
        createRSAPublicKey( &rsaKeyVal );
    }
    else
    {
        rv = JS_PKI_getECKeyVal( &binPri, &ecKeyVal );
        if( rv == 0 )
        {
            createECPrivateKey( &ecKeyVal );
            createECPublicKey( &ecKeyVal );
        }
    }

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_PKI_resetRSAKeyVal( &rsaKeyVal );
    JS_PKI_resetECKeyVal( &ecKeyVal );
    JS_PKI_resetCertInfo( &sCertInfo );

    if( rv == 0 )
    {
        manApplet->messageBox(tr("success to import pfx file"), this );
        manApplet->showTypeList( index, HM_ITEM_TYPE_PRIVATEKEY );
        QDialog::accept();
    }
    else
    {
        manApplet->warningBox( tr("fail to get key information"), this );
        QDialog::reject();
    }
}

void ImportPFXDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}


void ImportPFXDlg::clickPriPrivate()
{
    mPriPrivateCombo->setEnabled( mPriPrivateCheck->isChecked() );
}

void ImportPFXDlg::clickPriDecrypt()
{
    mPriDecryptCombo->setEnabled( mPriDecryptCheck->isChecked() );
}

void ImportPFXDlg::clickPriSign()
{
    mPriSignCombo->setEnabled(mPriSignCheck->isChecked());
}

void ImportPFXDlg::clickPriUnwrap()
{
    mPriUnwrapCombo->setEnabled(mPriUnwrapCheck->isChecked());
}
void ImportPFXDlg::clickPriModifiable()
{
    mPriModifiableCombo->setEnabled(mPriModifiableCheck->isChecked());
}
void ImportPFXDlg::clickPriSensitive()
{
    mPriSensitiveCombo->setEnabled(mPriSensitiveCheck->isChecked());
}
void ImportPFXDlg::clickPriDerive()
{
    mPriDeriveCombo->setEnabled(mPriDeriveCheck->isChecked());
}
void ImportPFXDlg::clickPriExtractable()
{
    mPriExtractableCombo->setEnabled(mPriExtractableCheck->isChecked());
}
void ImportPFXDlg::clickPriToken()
{
    mPriTokenCombo->setEnabled(mPriTokenCheck->isChecked());
}

void ImportPFXDlg::clickPriStartDate()
{
    mPriStartDateEdit->setEnabled(mPriStartDateCheck->isChecked());
}

void ImportPFXDlg::clickPriEndDate()
{
    mPriEndDateEdit->setEnabled(mPriEndDateCheck->isChecked());
}

void ImportPFXDlg::clickPubPrivate()
{
    mPubPrivateCombo->setEnabled(mPubPrivateCheck->isChecked());
}
void ImportPFXDlg::clickPubEncrypt()
{
    mPubEncryptCombo->setEnabled(mPubEncryptCheck->isChecked());
}
void ImportPFXDlg::clickPubWrap()
{
    mPubWrapCombo->setEnabled(mPubWrapCheck->isChecked());
}
void ImportPFXDlg::clickPubVerify()
{
    mPubVerifyCombo->setEnabled(mPubVerifyCheck->isChecked());
}
void ImportPFXDlg::clickPubDerive()
{
    mPubDeriveCombo->setEnabled(mPubDeriveCheck->isChecked());
}
void ImportPFXDlg::clickPubModifiable()
{
    mPubModifiableCombo->setEnabled(mPubModifiableCheck->isChecked());
}
void ImportPFXDlg::clickPubToken()
{
    mPubTokenCombo->setEnabled(mPubTokenCheck->isChecked());
}

void ImportPFXDlg::clickPubStartDate()
{
    mPubStartDateEdit->setEnabled(mPubStartDateCheck->isChecked());
}

void ImportPFXDlg::clickPubEndDate()
{
    mPubEndDateEdit->setEnabled(mPubEndDateCheck->isChecked());
}

void ImportPFXDlg::clickCertPrivate()
{
    mCertPrivateCombo->setEnabled(mCertPrivateCheck->isChecked());
}

void ImportPFXDlg::clickCertSensitive()
{
    mCertSensitiveCombo->setEnabled(mCertSensitiveCheck->isChecked());
}

void ImportPFXDlg::clickCertModifiable()
{
    mCertModifiableCombo->setEnabled(mCertModifiableCheck->isChecked());
}

void ImportPFXDlg::clickCertToken()
{
    mCertTokenCombo->setEnabled(mCertTokenCheck->isChecked());
}

void ImportPFXDlg::clickCertStartDate()
{
    mCertStartDateEdit->setEnabled(mCertStartDateCheck->isChecked());
}

void ImportPFXDlg::clickCertEndDate()
{
    mCertEndDateEdit->setEnabled(mCertEndDateCheck->isChecked());
}

void ImportPFXDlg::clickFind()
{
    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_PFX, strPath );
    if( fileName.isEmpty() ) return;

    mPFXPathText->setText( fileName );
}

void ImportPFXDlg::clickCertSubjectInCertCheck()
{
    bool bVal = mCertSubjectInCertCheck->isChecked();

    mCertSubjectText->setEnabled(!bVal );
}

void ImportPFXDlg::clickPriSubjectInCertCheck()
{
    bool bVal = mPriSubjectInCertCheck->isChecked();
    mPriSubjectText->setEnabled( !bVal );
}


int ImportPFXDlg::createCert( BIN *pCert )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = 0;
    CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = pCert->pVal;
    sTemplate[uCount].ulValueLen = pCert->nLen;
    uCount++;

    QString strLabel = mCertLabelText->text();
    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_decodeHex( strLabel.toStdString().c_str(), &binLabel );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mCertIDText->text();
    BIN binID = {0,0};

    if( !strID.isEmpty() )
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    QString strSubject;
    BIN binSubject = {0,0};

    if( mCertSubjectInCertCheck->isChecked() )
        strSubject = subject_in_cert_;
    else
        strSubject = mCertSubjectText->text();

    if( !strSubject.isEmpty() )
    {
        JS_BIN_set( &binSubject, (unsigned char *)strSubject.toStdString().c_str(), strSubject.length() );

        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
        uCount++;
    }


    if( mCertModifiableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = ( mCertModifiableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mCertPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = ( mCertPrivateCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mCertSensitiveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SENSITIVE;
        sTemplate[uCount].pValue = (mCertSensitiveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mCertTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = ( mCertTokenCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mCertStartDateCheck->isChecked() )
    {
        getCKDate( mCertStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mCertEndDateCheck->isChecked() )
    {
        getCKDate( mCertEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create certificate(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return -1;
    }

    return 0;
}

int ImportPFXDlg::createRSAPublicKey( JRSAKeyVal *pRsaKeyVal )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;

    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strLabel = mPubLabelText->text();
    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_decodeHex( strLabel.toStdString().c_str(), &binLabel );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mPubIDText->text();
    BIN binID = {0,0};

    if( !strID.isEmpty() )
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    BIN binModulus = {0,0};
    JS_BIN_decodeHex( pRsaKeyVal->pN, &binModulus );

    sTemplate[uCount].type = CKA_MODULUS;
    sTemplate[uCount].pValue = binModulus.pVal;
    sTemplate[uCount].ulValueLen = binModulus.nLen;
    uCount++;

    BIN binPublicExponent = {0,0};
    JS_BIN_decodeHex( pRsaKeyVal->pE, &binPublicExponent );

    sTemplate[uCount].type = CKA_PUBLIC_EXPONENT;
    sTemplate[uCount].pValue = binPublicExponent.pVal;
    sTemplate[uCount].ulValueLen = binPublicExponent.nLen;
    uCount++;

    if( mPubTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = ( mPubTokenCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = ( mPubPrivateCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubEncryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_ENCRYPT;
        sTemplate[uCount].pValue = ( mPubEncryptCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubWrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_WRAP;
        sTemplate[uCount].pValue = ( mPubWrapCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubVerifyCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_VERIFY;
        sTemplate[uCount].pValue = (mPubVerifyCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubModifiableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPubModifiableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubStartDateCheck->isChecked() )
    {
        getCKDate( mPubStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mPubEndDateCheck->isChecked() )
    {
        getCKDate( mPubEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create RSA public key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    return 0;
}

int ImportPFXDlg::createRSAPrivateKey( JRSAKeyVal *pRsaKeyVal )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;

    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strLabel = mPriLabelText->text();
    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_decodeHex( strLabel.toStdString().c_str(), &binLabel );

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mPriIDText->text();
    BIN binID = {0,0};

    if( !strID.isEmpty() )
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    QString strSubject;
    BIN binSubject = {0,0};

    if( mPriSubjectInCertCheck->isChecked() )
        strSubject = subject_in_cert_;
    else
        strSubject = mPriSubjectText->text();

    if( !strSubject.isEmpty() )
    {
        JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );

        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
        uCount++;
    }

    BIN binPublicExponent = {0,0};
    if( pRsaKeyVal->pE )
    {
        JS_BIN_decodeHex( pRsaKeyVal->pE, &binPublicExponent );
        sTemplate[uCount].type = CKA_PUBLIC_EXPONENT;
        sTemplate[uCount].pValue = binPublicExponent.pVal;
        sTemplate[uCount].ulValueLen = binPublicExponent.nLen;
        uCount++;
    }

    BIN binPrivateExponent = {0,0};
    if( pRsaKeyVal->pD )
    {
        JS_BIN_decodeHex( pRsaKeyVal->pD, &binPrivateExponent );
        sTemplate[uCount].type = CKA_PRIVATE_EXPONENT;
        sTemplate[uCount].pValue = binPrivateExponent.pVal;
        sTemplate[uCount].ulValueLen = binPrivateExponent.nLen;
        uCount++;
    }

    BIN binPrime1 = {0,0};
    if( pRsaKeyVal->pP )
    {
        JS_BIN_decodeHex( pRsaKeyVal->pP, &binPrime1 );
        sTemplate[uCount].type = CKA_PRIME_1;
        sTemplate[uCount].pValue = binPrime1.pVal;
        sTemplate[uCount].ulValueLen = binPrime1.nLen;
        uCount++;
    }

    BIN binPrime2 = {0,0};
    if( pRsaKeyVal->pQ )
    {
        JS_BIN_decodeHex( pRsaKeyVal->pQ, &binPrime2 );
        sTemplate[uCount].type = CKA_PRIME_2;
        sTemplate[uCount].pValue = binPrime2.pVal;
        sTemplate[uCount].ulValueLen = binPrime2.nLen;
        uCount++;
    }

    BIN binExponent1 = {0,0};
    if( pRsaKeyVal->pDMP1 )
    {
        JS_BIN_decodeHex( pRsaKeyVal->pDMP1, &binExponent1 );

        sTemplate[uCount].type = CKA_EXPONENT_1;
        sTemplate[uCount].pValue = binExponent1.pVal;
        sTemplate[uCount].ulValueLen = binExponent1.nLen;
        uCount++;
    }

    BIN binExponent2 = {0,0};
    if( pRsaKeyVal->pDMQ1 )
    {
        JS_BIN_decodeHex( pRsaKeyVal->pDMQ1, &binExponent2 );
        sTemplate[uCount].type = CKA_EXPONENT_2;
        sTemplate[uCount].pValue = binExponent2.pVal;
        sTemplate[uCount].ulValueLen = binExponent2.nLen;
        uCount++;
    }

    BIN binCoefficient = {0,0};
    if( pRsaKeyVal->pIQMP )
    {
        JS_BIN_decodeHex( pRsaKeyVal->pIQMP, &binCoefficient );
        sTemplate[uCount].type = CKA_COEFFICIENT;
        sTemplate[uCount].pValue = binCoefficient.pVal;
        sTemplate[uCount].ulValueLen = binCoefficient.nLen;
        uCount++;
    }

    if( mPriPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = ( mPriPrivateCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = (mPriTokenCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriDecryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DECRYPT;
        sTemplate[uCount].pValue = (mPriDecryptCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriUnwrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_UNWRAP;
        sTemplate[uCount].pValue = (mPriUnwrapCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriModifiableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPriModifiableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriSensitiveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPriSensitiveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriDeriveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPriDeriveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriExtractableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPriExtractableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriSignCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPriSignCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriStartDateCheck->isChecked() )
    {
        getCKDate( mPriStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mPriEndDateCheck->isChecked() )
    {
        getCKDate( mPriEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create RSA private key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    return 0;
}

int ImportPFXDlg::createECPublicKey( JECKeyVal *pEcKeyVal )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_EC;

    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strLabel = mPubLabelText->text();
    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_decodeHex( strLabel.toStdString().c_str(), &binLabel );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mPubIDText->text();
    BIN binID = {0,0};

    if( !strID.isEmpty() )
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    BIN binECParam = {0,0};
    JS_BIN_decodeHex( pEcKeyVal->pGroup, &binECParam );

    sTemplate[uCount].type = CKA_EC_PARAMS;
    sTemplate[uCount].pValue = binECParam.pVal;
    sTemplate[uCount].ulValueLen = binECParam.nLen;
    uCount++;

    BIN binECPoint={0,0};
    BIN binPubX = {0,0};
    BIN binPubY = {0,0};

    JS_BIN_decodeHex( pEcKeyVal->pPubX, &binPubX );
    JS_BIN_decodeHex( pEcKeyVal->pPubY, &binPubY );
    JS_BIN_decodeHex( "04", &binECPoint );
    JS_BIN_appendBin( &binECPoint, &binPubX );
    JS_BIN_appendBin( &binECPoint, &binPubY );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );

    sTemplate[uCount].type = CKA_EC_POINT;
    sTemplate[uCount].pValue = binECPoint.pVal;
    sTemplate[uCount].ulValueLen = binECPoint.nLen;
    uCount++;

    if( mPubTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = ( mPubTokenCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = (mPubPrivateCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubEncryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_ENCRYPT;
        sTemplate[uCount].pValue = (mPubEncryptCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubWrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_WRAP;
        sTemplate[uCount].pValue = (mPubWrapCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubVerifyCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_VERIFY;
        sTemplate[uCount].pValue = (mPubVerifyCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubModifiableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPubModifiableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubStartDateCheck->isChecked() )
    {
        getCKDate( mPubStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mPubEndDateCheck->isChecked() )
    {
        getCKDate( mPubEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create EC public key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        return rv;
    }

    return 0;
}

int ImportPFXDlg::createECPrivateKey( JECKeyVal *pEcKeyVal )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();


    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC;

    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strLabel = mPriLabelText->text();
    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_decodeHex( strLabel.toStdString().c_str(), &binLabel );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mPriIDText->text();
    BIN binID = {0,0};

    if( !strID.isEmpty() )
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    QString strSubject;
    BIN binSubject = {0,0};

    if( mPriSubjectInCertCheck->isChecked() )
        strSubject = subject_in_cert_;
    else
        strSubject = mPriSubjectText->text();

    if( !strSubject.isEmpty() )
    {
        JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );
        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
        uCount++;
    }

    BIN binECParam = {0,0};
    JS_BIN_decodeHex( pEcKeyVal->pGroup, &binECParam );

    sTemplate[uCount].type = CKA_EC_PARAMS;
    sTemplate[uCount].pValue = binECParam.pVal;
    sTemplate[uCount].ulValueLen = binECParam.nLen;
    uCount++;

    BIN binValue = {0,0};
    JS_BIN_decodeHex( pEcKeyVal->pPrivate, &binValue );

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = binValue.pVal;
    sTemplate[uCount].ulValueLen = binValue.nLen;
    uCount++;

    if( mPriPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = ( mPriPrivateCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = (mPriTokenCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriDecryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DECRYPT;
        sTemplate[uCount].pValue = (mPriDecryptCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriUnwrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_UNWRAP;
        sTemplate[uCount].pValue = (mPriUnwrapCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriModifiableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPriModifiableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriSensitiveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPriSensitiveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriDeriveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPriDeriveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriExtractableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPriExtractableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriSignCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPriSignCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriStartDateCheck->isChecked() )
    {
        getCKDate( mPriStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mPriEndDateCheck->isChecked() )
    {
        getCKDate( mPriEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create EC private key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        return rv;
    }

    return 0;
}

void ImportPFXDlg::setDefaults()
{
    mCertLabelText->setText( "Certificate Label" );
    mCertIDText->setText( "Certificate ID" );

    mCertTokenCheck->setChecked(true);
    mCertTokenCombo->setEnabled(true);
    mCertTokenCombo->setCurrentIndex(1);

    mPubLabelText->setText( "Public Label" );
    mPubIDText->setText( "Public ID" );

    mPubEncryptCheck->setChecked(true);
    mPubEncryptCombo->setEnabled(true);
    mPubEncryptCombo->setCurrentIndex(1);


    mPubTokenCheck->setChecked(true);
    mPubTokenCombo->setEnabled(true);
    mPubTokenCombo->setCurrentIndex(1);

    mPubVerifyCheck->setChecked(true);
    mPubVerifyCombo->setEnabled(true);
    mPubVerifyCombo->setCurrentIndex(1);

    mPriLabelText->setText( "Private Label" );
    mPriSubjectText->setText( "CN=SubjectDN" );
    mPriIDText->setText( "Private ID" );

    mPriPrivateCheck->setChecked(true);
    mPriPrivateCombo->setEnabled(true);
    mPriPrivateCombo->setCurrentIndex(1);


    mPriSignCheck->setChecked(true);
    mPriSignCombo->setEnabled(true);
    mPriSignCombo->setCurrentIndex(1);

    mPriDecryptCheck->setChecked(true);
    mPriDecryptCombo->setEnabled(true);
    mPriDecryptCombo->setCurrentIndex(1);

    mPriTokenCheck->setChecked(true);
    mPriTokenCombo->setEnabled(true);
    mPriTokenCombo->setCurrentIndex(1);

    QDateTime nowTime;
    nowTime.setTime_t( time(NULL) );

    mPriStartDateEdit->setDate( nowTime.date() );
    mPriEndDateEdit->setDate( nowTime.date() );

    mPubStartDateEdit->setDate( nowTime.date() );
    mPubEndDateEdit->setDate( nowTime.date() );

    mCertStartDateEdit->setDate( nowTime.date() );
    mCertEndDateEdit->setDate( nowTime.date() );
}
