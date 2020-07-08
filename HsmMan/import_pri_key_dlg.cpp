#include <QFileDialog>

#include "import_pri_key_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

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

    clickPubImport();
}

void ImportPriKeyDlg::initAttributes()
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

}

void ImportPriKeyDlg::setAttributes()
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

    mPubPrivateCombo->setEnabled( mPubPrivateCheck->isChecked() );
    mPubEncryptCombo->setEnabled( mPubEncryptCheck->isChecked() );
    mPubWrapCombo->setEnabled( mPubWrapCheck->isChecked() );
    mPubVerifyCombo->setEnabled( mPubVerifyCheck->isChecked() );
    mPubDeriveCombo->setEnabled( mPubDeriveCheck->isChecked() );
    mPubModifiableCombo->setEnabled( mPubModifiableCheck->isChecked() );
    mPubTokenCombo->setEnabled( mPubTokenCheck->isChecked() );

}

void ImportPriKeyDlg::connectAttributes()
{
    connect( mPubImportCheck, SIGNAL(clicked()), this, SLOT(clickPubImport()));

    connect( mPriPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPriPrivate()));
    connect( mPriDecryptCheck, SIGNAL(clicked()), this, SLOT(clickPriDecrypt()));
    connect( mPriSignCheck, SIGNAL(clicked()), this, SLOT(clickPriSign()));
    connect( mPriUnwrapCheck, SIGNAL(clicked()), this, SLOT(clickPriUnwrap()));
    connect( mPriModifiableCheck, SIGNAL(clicked()), this, SLOT(clickPriModifiable()));
    connect( mPriSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickPriSensitive()));
    connect( mPriDeriveCheck, SIGNAL(clicked()), this, SLOT(clickPriDerive()));
    connect( mPriExtractableCheck, SIGNAL(clicked()), this, SLOT(clickPriExtractable()));
    connect( mPriTokenCheck, SIGNAL(clicked()), this, SLOT(clickPriToken()));

    connect( mPubPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPubPrivate()));
    connect( mPubEncryptCheck, SIGNAL(clicked()), this, SLOT(clickPubEncrypt()));
    connect( mPubWrapCheck, SIGNAL(clicked()), this, SLOT(clickPubWrap()));
    connect( mPubVerifyCheck, SIGNAL(clicked()), this, SLOT(clickPubVerify()));
    connect( mPubDeriveCheck, SIGNAL(clicked()), this, SLOT(clickPubDerive()));
    connect( mPubModifiableCheck, SIGNAL(clicked()), this, SLOT(clickPubModifiable()));
    connect( mPubTokenCheck, SIGNAL(clicked()), this, SLOT(clickPubToken()));


    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));
}

void ImportPriKeyDlg::accept()
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;


    QString strPriPath = mPathText->text();

    if( strPriPath.isEmpty() )
    {
        manApplet->warningBox( tr("You have to select private key file."), this );
        return;
    }


    BIN binPri = {0,0};
    JRSAKeyVal rsaKeyVal;
    JECKeyVal ecKeyVal;;

    memset( &rsaKeyVal, 0x00, sizeof(JRSAKeyVal));
    memset( &ecKeyVal, 0x00, sizeof(JECKeyVal));

    JS_BIN_fileRead( strPriPath.toStdString().c_str(), &binPri );

    rv = JS_PKI_getRSAKeyVal( &binPri, &rsaKeyVal );
    if( rv == 0 )
    {
        rv = createRSAPrivateKey( &rsaKeyVal );
        if( rv != 0 ) goto end;

        if( mPubImportCheck->isChecked() )
            rv = createRSAPublicKey( &rsaKeyVal );
    }
    else
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

end :

    if( rv != 0 )
    {
        manApplet->warningBox( tr("fail to get key information."), this );
        return;
    }

    manApplet->messageBox( tr("success to import private key"), this );
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

void ImportPriKeyDlg::clickPubImport()
{
    bool bVal = mPubImportCheck->isChecked();

    mTabWidget->setTabEnabled( 2, bVal );
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


void ImportPriKeyDlg::clickFind()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strPath = QDir::currentPath();

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Private Key"),
                                                     strPath,
                                                     tr("DER Files (*.der);;Key Files (*.key);;All Files (*.*)"),
                                                     &selectedFilter,
                                                     options );

    mPathText->setText( fileName );
}



int ImportPriKeyDlg::createRSAPublicKey( JRSAKeyVal *pRsaKeyVal )
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strLabel = mPubLabelText->text();

    if( !strLabel.isEmpty() )
    {
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = (unsigned char *)strLabel.toStdString().c_str();
        sTemplate[uCount].ulValueLen = strLabel.length();
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

    rv = JS_PKCS11_CreateObject( p11_ctx, sTemplate, uCount, &hObject );
    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create RSA public key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createRSAPrivateKey( JRSAKeyVal *pRsaKeyVal )
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strLabel = mPriLabelText->text();

    if( !strLabel.isEmpty() )
    {   
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = (unsigned char *)strLabel.toStdString().c_str();
        sTemplate[uCount].ulValueLen = strLabel.length();
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

    rv = JS_PKCS11_CreateObject(p11_ctx, sTemplate, uCount, &hObject );
    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create RSA private key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createECPublicKey( JECKeyVal *pEcKeyVal )
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_EC;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strLabel = mPubLabelText->text();

    if( !strLabel.isEmpty() )
    {
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = (unsigned char *)strLabel.toStdString().c_str();
        sTemplate[uCount].ulValueLen = strLabel.length();
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
    JS_BIN_decodeHex( pEcKeyVal->pECPoint, &binECPoint );

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

    rv = JS_PKCS11_CreateObject( p11_ctx, sTemplate, uCount, &hObject );
    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create EC public key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createECPrivateKey( JECKeyVal *pEcKeyVal )
{
    JP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    p11_ctx->hSession = slotInfo.getSessionHandle();


    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = -1;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strLabel = mPriLabelText->text();

    if( !strLabel.isEmpty() )
    {
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = (unsigned char *)strLabel.toStdString().c_str();
        sTemplate[uCount].ulValueLen = strLabel.length();
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

    rv = JS_PKCS11_CreateObject( p11_ctx, sTemplate, uCount, &hObject );
    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create EC private key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        return rv;
    }

    return 0;
}

void ImportPriKeyDlg::setDefaults()
{
    mPubLabelText->setText( "Public Label" );
    mPubIDText->setText( "Public ID" );

    mPriLabelText->setText( "Private Label" );
    mPriSubjectText->setText( "CN=SubjectDN" );
    mPriIDText->setText( "Private ID" );


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
}
