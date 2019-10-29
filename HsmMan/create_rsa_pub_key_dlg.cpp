#include "create_rsa_pub_key_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

static QStringList sFalseTrue = { "false", "true" };

CreateRSAPubKeyDlg::CreateRSAPubKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
}

CreateRSAPubKeyDlg::~CreateRSAPubKeyDlg()
{

}

void CreateRSAPubKeyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void CreateRSAPubKeyDlg::showEvent(QShowEvent* event )
{
    initialize();
    setDefaults();
}

void CreateRSAPubKeyDlg::initialize()
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

void CreateRSAPubKeyDlg::initAttributes()
{
    mPrivateCombo->addItems(sFalseTrue);
    mEncryptCombo->addItems(sFalseTrue);
    mWrapCombo->addItems(sFalseTrue);
    mVerifyCombo->addItems(sFalseTrue);
    mDeriveCombo->addItems(sFalseTrue);
    mModifiableCombo->addItems(sFalseTrue);
    mTokenCombo->addItems(sFalseTrue);
}

void CreateRSAPubKeyDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void CreateRSAPubKeyDlg::connectAttributes()
{
    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mEncryptCheck, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mWrapCheck, SIGNAL(clicked()), this, SLOT(clickWrap()));
    connect( mVerifyCheck, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mDeriveCheck, SIGNAL(clicked()), this, SLOT(clickDerive()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
}

void CreateRSAPubKeyDlg::accept()
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;

    hSession = slotInfo.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL    bTrue = CK_TRUE;
    CK_BBOOL    bFalse = CK_FALSE;
    CK_OBJECT_HANDLE    hObject = 0;

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

    QString strModulus = mModulesText->text();
    BIN binModulus = {0,0};

    if( !strModulus.isEmpty() )
    {
        JS_BIN_decodeHex( strModulus.toStdString().c_str(), &binModulus );
        sTemplate[uCount].type = CKA_MODULUS;
        sTemplate[uCount].pValue = binModulus.pVal;
        sTemplate[uCount].ulValueLen = binModulus.nLen;
        uCount++;
    }

    QString strExponent = mExponentText->text();
    BIN binExponent = {0,0};

    if( !strExponent.isEmpty() )
    {
        JS_BIN_decodeHex( strExponent.toStdString().c_str(), &binExponent );
        sTemplate[uCount].type = CKA_PUBLIC_EXPONENT;
        sTemplate[uCount].pValue = binExponent.pVal;
        sTemplate[uCount].ulValueLen = binExponent.nLen;
        uCount++;
    }

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

    if( mDeriveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DERIVE;
        sTemplate[uCount].pValue = ( mDeriveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mEncryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_ENCRYPT;
        sTemplate[uCount].pValue = ( mEncryptCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mVerifyCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_VERIFY;
        sTemplate[uCount].pValue = ( mVerifyCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mWrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_WRAP;
        sTemplate[uCount].pValue = ( mWrapCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    rv = JS_PKCS11_CreateObject( p11_ctx, hSession, sTemplate, uCount, &hObject );
    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("fail to create RSA public key(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox( tr("Success to create RSA public key"), this );

    QDialog::accept();
}


void CreateRSAPubKeyDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void CreateRSAPubKeyDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void CreateRSAPubKeyDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void CreateRSAPubKeyDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}

void CreateRSAPubKeyDlg::clickDerive()
{
    mDeriveCombo->setEnabled(mDeriveCheck->isChecked());
}

void CreateRSAPubKeyDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void CreateRSAPubKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void CreateRSAPubKeyDlg::setDefaults()
{
    mLabelText->setText( "Publick Key Label" );
    mExponentText->setText( "010001" );
    mIDText->setText( "Public Key ID" );

    mEncryptCheck->setChecked(true);
    mEncryptCombo->setEnabled(true);
    mEncryptCombo->setCurrentIndex(1);


    mTokenCheck->setChecked(true);
    mTokenCombo->setEnabled(true);
    mTokenCombo->setCurrentIndex(1);

    mVerifyCheck->setChecked(true);
    mVerifyCombo->setEnabled(true);
    mVerifyCombo->setCurrentIndex(1);
}
