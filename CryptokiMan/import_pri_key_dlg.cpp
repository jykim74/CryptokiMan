#include <QFileDialog>

#include "import_pri_key_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "js_pki_tools.h"
#include "common.h"
#include "cryptoki_api.h"

static QStringList sFalseTrue = { "false", "true" };

ImportPriKeyDlg::ImportPriKeyDlg(QWidget *parent) :
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
}

ImportPriKeyDlg::~ImportPriKeyDlg()
{

}

void ImportPriKeyDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void ImportPriKeyDlg::initialize()
{
    mSlotsCombo->clear();

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    for( int i=0; i < slot_infos.size(); i++ )
    {
        SlotInfo slotInfo = slot_infos.at(i);

        mSlotsCombo->addItem( slotInfo.getDesc() );
    }

    if( slot_infos.size() > 0 ) slotChanged(0);

    checkPubImport();
    checkEncPriKey();
}

void ImportPriKeyDlg::initAttributes()
{
    mPriPrivateCombo->addItems( sFalseTrue );
    mPriDecryptCombo->addItems( sFalseTrue );
    mPriSignCombo->addItems( sFalseTrue );
    mPriSignRecoverCombo->addItems(sFalseTrue);
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
    mPubVerifyRecoverCombo->addItems(sFalseTrue);
    mPubDeriveCombo->addItems( sFalseTrue );
    mPubModifiableCombo->addItems( sFalseTrue );
    mPubTokenCombo->addItems( sFalseTrue );
    mPubTrustedCombo->addItems( sFalseTrue );

    QDate nowDate = QDate::currentDate();
    mPriStartDateEdit->setDate(nowDate);
    mPriEndDateEdit->setDate(nowDate);
    mPubStartDateEdit->setDate(nowDate);
    mPubEndDateEdit->setDate(nowDate);
}

void ImportPriKeyDlg::setAttributes()
{
    mPriPrivateCombo->setEnabled( mPriPrivateCheck->isChecked() );
    mPriDecryptCombo->setEnabled( mPriDecryptCheck->isChecked() );
    mPriSignCombo->setEnabled( mPriSignCheck->isChecked() );
    mPriSignRecoverCombo->setEnabled( mPriSignRecoverCheck->isChecked());
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
    mPubVerifyRecoverCombo->setEnabled( mPubVerifyRecoverCheck->isChecked() );
    mPubDeriveCombo->setEnabled( mPubDeriveCheck->isChecked() );
    mPubModifiableCombo->setEnabled( mPubModifiableCheck->isChecked() );
    mPubTokenCombo->setEnabled( mPubTokenCheck->isChecked() );
    mPubTrustedCombo->setEnabled( mPubTrustedCheck->isChecked() );
    mPubStartDateEdit->setEnabled( mPubStartDateCheck->isChecked() );
    mPubEndDateEdit->setEnabled( mPubEndDateCheck->isChecked() );

}

void ImportPriKeyDlg::connectAttributes()
{
    connect( mPubImportCheck, SIGNAL(clicked()), this, SLOT(checkPubImport()));
    connect( mEncPriKeyCheck, SIGNAL(clicked()), this, SLOT(checkEncPriKey()));

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
    connect( mPubTrustedCheck, SIGNAL(clicked()), this, SLOT(clickPubTrusted()));
    connect( mPubStartDateCheck, SIGNAL(clicked()), this, SLOT(clickPubStartDate()));
    connect( mPubEndDateCheck, SIGNAL(clicked()), this, SLOT(clickPubEndDate()));


    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));
}

int ImportPriKeyDlg::readPrivateKey( BIN *pPriKey )
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binDec = {0,0};
    BIN binInfo = {0,0};

    QString strPriPath = mPathText->text();

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        manApplet->warningBox( tr( "fail to read private key: %1").arg( ret ), this );
        return  -1;
    }

    if( mEncPriKeyCheck->isChecked() )
    {
        QString strPasswd = mPasswdText->text();
        if( strPasswd.length() < 1 )
        {
            manApplet->warningBox( tr( "You have to insert password"), this );
            ret = -1;
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
        if( ret != 0 )
        {
            manApplet->warningBox( tr( "fail to decrypt private key:%1").arg( ret ), this );
            mPasswdText->setFocus();
            ret = -1;
            goto end;
        }

        JS_BIN_copy( pPriKey, &binDec );
        ret = 0;
    }
    else
    {
        JS_BIN_copy( pPriKey, &binData );
        ret = 0;
    }

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binDec );
    JS_BIN_reset( &binInfo );

    return ret;
}

void ImportPriKeyDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    int nKeyType = -1;

    BIN binPri = {0,0};
    JRSAKeyVal rsaKeyVal;
    JECKeyVal ecKeyVal;
    JDSAKeyVal dsaKeyVal;

    memset( &rsaKeyVal, 0x00, sizeof(JRSAKeyVal));
    memset( &ecKeyVal, 0x00, sizeof(JECKeyVal));
    memset( &dsaKeyVal, 0x00, sizeof(JDSAKeyVal));

    rv = readPrivateKey( &binPri );
    if( rv != 0 ) return;

    nKeyType = JS_PKI_getPriKeyType( &binPri );

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        rv = JS_PKI_getRSAKeyVal( &binPri, &rsaKeyVal );
        if( rv == 0 )
        {
            rv = createRSAPrivateKey( &rsaKeyVal );
            if( rv != 0 ) goto end;

            if( mPubImportCheck->isChecked() )
                rv = createRSAPublicKey( &rsaKeyVal );
        }
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC )
    {
        rv = JS_PKI_getECKeyVal( &binPri, &ecKeyVal );
        if( rv == 0 )
        {
            rv = createECPrivateKey( &ecKeyVal );
            if( rv != 0 ) goto end;

            if( mPubImportCheck->isChecked() )
                rv = createECPublicKey( &ecKeyVal );
        }
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_DSA )
    {
        rv = JS_PKI_getDSAKeyVal( &binPri, &dsaKeyVal );
        if( rv == 0 )
        {
            rv = createDSAPrivateKey( &dsaKeyVal );
            if( rv != 0 ) goto end;

            if( mPubImportCheck->isChecked() )
                rv = createDSAPublicKey( &dsaKeyVal );
        }
    }
    else
    {
        manApplet->elog( QString( "Not support key type: %1").arg(nKeyType));
        rv = -1;
        goto end;
    }

end :
    JS_BIN_reset( &binPri );
    JS_PKI_resetRSAKeyVal( &rsaKeyVal );
    JS_PKI_resetECKeyVal( &ecKeyVal );
    JS_PKI_resetDSAKeyVal( &dsaKeyVal );

    if( rv != 0 )
    {
        manApplet->warningBox( tr("fail to get key information."), this );
        return;
    }

    manApplet->messageBox( tr("success to import private key"), this );
    manApplet->showTypeList( index, HM_ITEM_TYPE_PRIVATEKEY );

    QDialog::accept();
}

void ImportPriKeyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void ImportPriKeyDlg::checkPubImport()
{
    bool bVal = mPubImportCheck->isChecked();

    tabWidget->setTabEnabled( 2, bVal );
}

void ImportPriKeyDlg::checkEncPriKey()
{
    bool bVal = mEncPriKeyCheck->isChecked();

    mPasswdLabel->setEnabled(bVal);
    mPasswdText->setEnabled(bVal);
}

void ImportPriKeyDlg::clickPriPrivate()
{
    mPriPrivateCombo->setEnabled( mPriPrivateCheck->isChecked() );
}

void ImportPriKeyDlg::clickPriDecrypt()
{
    mPriDecryptCombo->setEnabled( mPriDecryptCheck->isChecked() );
}

void ImportPriKeyDlg::clickPriSign()
{
    mPriSignCombo->setEnabled(mPriSignCheck->isChecked());
}

void ImportPriKeyDlg::clickPriSignRecover()
{
    mPriSignRecoverCombo->setEnabled(mPriSignRecoverCheck->isChecked());
}

void ImportPriKeyDlg::clickPriUnwrap()
{
    mPriUnwrapCombo->setEnabled(mPriUnwrapCheck->isChecked());
}
void ImportPriKeyDlg::clickPriModifiable()
{
    mPriModifiableCombo->setEnabled(mPriModifiableCheck->isChecked());
}
void ImportPriKeyDlg::clickPriSensitive()
{
    mPriSensitiveCombo->setEnabled(mPriSensitiveCheck->isChecked());
}
void ImportPriKeyDlg::clickPriDerive()
{
    mPriDeriveCombo->setEnabled(mPriDeriveCheck->isChecked());
}
void ImportPriKeyDlg::clickPriExtractable()
{
    mPriExtractableCombo->setEnabled(mPriExtractableCheck->isChecked());
}
void ImportPriKeyDlg::clickPriToken()
{
    mPriTokenCombo->setEnabled(mPriTokenCheck->isChecked());
}

void ImportPriKeyDlg::clickPriStartDate()
{
    mPriStartDateEdit->setEnabled( mPriStartDateCheck->isChecked() );
}
void ImportPriKeyDlg::clickPriEndDate()
{
    mPriEndDateEdit->setEnabled( mPriEndDateCheck->isChecked());
}

void ImportPriKeyDlg::clickPubPrivate()
{
    mPubPrivateCombo->setEnabled(mPubPrivateCheck->isChecked());
}
void ImportPriKeyDlg::clickPubEncrypt()
{
    mPubEncryptCombo->setEnabled(mPubEncryptCheck->isChecked());
}
void ImportPriKeyDlg::clickPubWrap()
{
    mPubWrapCombo->setEnabled(mPubWrapCheck->isChecked());
}
void ImportPriKeyDlg::clickPubVerify()
{
    mPubVerifyCombo->setEnabled(mPubVerifyCheck->isChecked());
}

void ImportPriKeyDlg::clickPubVerifyRecover()
{
    mPubVerifyRecoverCombo->setEnabled(mPubVerifyRecoverCheck->isChecked());
}

void ImportPriKeyDlg::clickPubDerive()
{
    mPubDeriveCombo->setEnabled(mPubDeriveCheck->isChecked());
}
void ImportPriKeyDlg::clickPubModifiable()
{
    mPubModifiableCombo->setEnabled(mPubModifiableCheck->isChecked());
}

void ImportPriKeyDlg::clickPubToken()
{
    mPubTokenCombo->setEnabled(mPubTokenCheck->isChecked());
}

void ImportPriKeyDlg::clickPubTrusted()
{
    mPubTrustedCombo->setEnabled(mPubTrustedCheck->isChecked());
}

void ImportPriKeyDlg::clickPubStartDate()
{
    mPubStartDateEdit->setEnabled( mPubStartDateCheck->isChecked());
}

void ImportPriKeyDlg::clickPubEndDate()
{
    mPubEndDateEdit->setEnabled( mPubEndDateCheck->isChecked() );
}

void ImportPriKeyDlg::clickFind()
{
    QString strPath = manApplet->curFolder();
    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mPathText->setText( fileName );
    manApplet->setCurFile( fileName );
}



int ImportPriKeyDlg::createRSAPublicKey( JRSAKeyVal *pRsaKeyVal )
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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strSubject = mPubSubjectText->text();
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );

        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
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

    if( mPubTrustedCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TRUSTED;
        sTemplate[uCount].pValue = ( mPubTrustedCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mPubVerifyRecoverCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_VERIFY_RECOVER;
        sTemplate[uCount].pValue = (mPubVerifyRecoverCombo->currentIndex() ? &bTrue : &bFalse );
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

    JS_BIN_reset( &binID );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binModulus );
    JS_BIN_reset( &binPublicExponent );
    JS_BIN_reset( &binLabel );


    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create RSA public key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createRSAPrivateKey( JRSAKeyVal *pRsaKeyVal )
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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.length() );
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

    QString strSubject = mPriSubjectText->text();
    BIN binSubject = {0,0};

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

    BIN binModules = {0,0};
    if( pRsaKeyVal->pN )
    {
        JS_BIN_decodeHex( pRsaKeyVal->pN, &binModules );
        sTemplate[uCount].type = CKA_MODULUS;
        sTemplate[uCount].pValue = binModules.pVal;
        sTemplate[uCount].ulValueLen = binModules.nLen;
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
        sTemplate[uCount].type = CKA_SENSITIVE;
        sTemplate[uCount].pValue = (mPriSensitiveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriDeriveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DERIVE;
        sTemplate[uCount].pValue = (mPriDeriveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriExtractableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_EXTRACTABLE;
        sTemplate[uCount].pValue = (mPriExtractableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriSignCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN;
        sTemplate[uCount].pValue = (mPriSignCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriSignRecoverCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN_RECOVER;
        sTemplate[uCount].pValue = (mPriSignRecoverCombo->currentIndex() ? &bTrue : &bFalse );
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

    JS_BIN_reset( &binID );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binPublicExponent );
    JS_BIN_reset( &binModules );
    JS_BIN_reset( &binPrivateExponent );
    JS_BIN_reset( &binPrime1 );
    JS_BIN_reset( &binPrime2 );
    JS_BIN_reset( &binExponent1 );
    JS_BIN_reset( &binExponent2 );
    JS_BIN_reset( &binCoefficient );
    JS_BIN_reset( &binLabel );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create RSA private key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createECPublicKey( JECKeyVal *pEcKeyVal )
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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strSubject = mPubSubjectText->text();
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );

        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
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
    JS_PKI_getOIDFromString( pEcKeyVal->pCurveOID, &binECParam );


    sTemplate[uCount].type = CKA_EC_PARAMS;
    sTemplate[uCount].pValue = binECParam.pVal;
    sTemplate[uCount].ulValueLen = binECParam.nLen;
    uCount++;

    BIN binECPoint={0,0};
    BIN binPubX = {0,0};
    BIN binPubY = {0,0};
    unsigned char sPrefix[3];

    JS_BIN_decodeHex( pEcKeyVal->pPubX, &binPubX );
    JS_BIN_decodeHex( pEcKeyVal->pPubY, &binPubY );
//    JS_BIN_decodeHex( "04", &binECPoint );
    sPrefix[0] = 0x04;
    sPrefix[1] = binPubX.nLen + binPubY.nLen + 1;
    sPrefix[2] = 0x04;

    JS_BIN_set( &binECPoint, sPrefix, 3 );
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

    if( mPubTrustedCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TRUSTED;
        sTemplate[uCount].pValue = ( mPubTrustedCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mPubVerifyRecoverCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_VERIFY_RECOVER;
        sTemplate[uCount].pValue = (mPubVerifyRecoverCombo->currentIndex() ? &bTrue : &bFalse );
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

    JS_BIN_reset( &binID );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binECParam );
    JS_BIN_reset( &binECPoint );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );
    JS_BIN_reset( &binLabel );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create EC public key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createECPrivateKey( JECKeyVal *pEcKeyVal )
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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.length() );
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

    QString strSubject = mPriSubjectText->text();
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );
        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
        uCount++;
    }

    BIN binECParam = {0,0};
    JS_PKI_getOIDFromString( pEcKeyVal->pCurveOID, &binECParam );

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
        sTemplate[uCount].type = CKA_SENSITIVE;
        sTemplate[uCount].pValue = (mPriSensitiveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriDeriveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DERIVE;
        sTemplate[uCount].pValue = (mPriDeriveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriExtractableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_EXTRACTABLE;
        sTemplate[uCount].pValue = (mPriExtractableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriSignCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN;
        sTemplate[uCount].pValue = (mPriSignCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriSignRecoverCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN_RECOVER;
        sTemplate[uCount].pValue = (mPriSignRecoverCombo->currentIndex() ? &bTrue : &bFalse );
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

    JS_BIN_reset( &binID );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binECParam );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binLabel );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create EC private key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createDSAPublicKey( JDSAKeyVal *pDSAKeyVal )
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
    CK_KEY_TYPE keyType = CKK_DSA;

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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.length() );

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strSubject = mPubSubjectText->text();
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );

        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
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

    BIN binP={0,0};
    BIN binQ = {0,0};
    BIN binG = {0,0};
    BIN binPub = {0,0};

    JS_BIN_decodeHex( pDSAKeyVal->pP, &binP );
    JS_BIN_decodeHex( pDSAKeyVal->pQ, &binQ );
    JS_BIN_decodeHex( pDSAKeyVal->pG, &binG );
    JS_BIN_decodeHex( pDSAKeyVal->pPublic, &binPub );

    sTemplate[uCount].type = CKA_PRIME;
    sTemplate[uCount].pValue = binP.pVal;
    sTemplate[uCount].ulValueLen = binP.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_SUBPRIME;
    sTemplate[uCount].pValue = binQ.pVal;
    sTemplate[uCount].ulValueLen = binQ.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_BASE;
    sTemplate[uCount].pValue = binG.pVal;
    sTemplate[uCount].ulValueLen = binG.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = binPub.pVal;
    sTemplate[uCount].ulValueLen = binPub.nLen;
    uCount++;

    if( mPubTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = ( mPubTokenCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubTrustedCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TRUSTED;
        sTemplate[uCount].pValue = ( mPubTrustedCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mPubVerifyRecoverCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_VERIFY_RECOVER;
        sTemplate[uCount].pValue = (mPubVerifyRecoverCombo->currentIndex() ? &bTrue : &bFalse );
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

    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binPub );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create DSA public key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createDSAPrivateKey( JDSAKeyVal *pDSAKeyVal )
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
    CK_KEY_TYPE keyType = CKK_DSA;

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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.length() );

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

    if( !strSubject.isEmpty() )
    {
        JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );
        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
        uCount++;
    }

    BIN binP={0,0};
    BIN binQ = {0,0};
    BIN binG = {0,0};

    JS_BIN_decodeHex( pDSAKeyVal->pP, &binP );
    JS_BIN_decodeHex( pDSAKeyVal->pQ, &binQ );
    JS_BIN_decodeHex( pDSAKeyVal->pG, &binG );

    sTemplate[uCount].type = CKA_PRIME;
    sTemplate[uCount].pValue = binP.pVal;
    sTemplate[uCount].ulValueLen = binP.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_SUBPRIME;
    sTemplate[uCount].pValue = binQ.pVal;
    sTemplate[uCount].ulValueLen = binQ.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_BASE;
    sTemplate[uCount].pValue = binG.pVal;
    sTemplate[uCount].ulValueLen = binG.nLen;
    uCount++;


    BIN binValue = {0,0};
    JS_BIN_decodeHex( pDSAKeyVal->pPrivate, &binValue );

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
        sTemplate[uCount].type = CKA_SENSITIVE;
        sTemplate[uCount].pValue = (mPriSensitiveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriDeriveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DERIVE;
        sTemplate[uCount].pValue = (mPriDeriveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriExtractableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_EXTRACTABLE;
        sTemplate[uCount].pValue = (mPriExtractableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriSignCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN;
        sTemplate[uCount].pValue = (mPriSignCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriSignRecoverCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN_RECOVER;
        sTemplate[uCount].pValue = (mPriSignRecoverCombo->currentIndex() ? &bTrue : &bFalse );
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

    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binG );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create DSA private key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        return rv;
    }

    return 0;
}


void ImportPriKeyDlg::setDefaults()
{
    const QString strDefaultID = "0102030405060708";

    mPubLabelText->setText( "Public Label" );
    mPubIDText->setText( strDefaultID );

    mPriLabelText->setText( "Private Label" );
    mPriIDText->setText( strDefaultID );

    mPubEncryptCheck->setChecked(true);
    mPubEncryptCombo->setEnabled(true);
    mPubEncryptCombo->setCurrentIndex(1);

    mPubTokenCheck->setChecked(true);
    mPubTokenCombo->setEnabled(true);
    mPubTokenCombo->setCurrentIndex(1);

    mPubVerifyCheck->setChecked(true);
    mPubVerifyCombo->setEnabled(true);
    mPubVerifyCombo->setCurrentIndex(1);


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
}
