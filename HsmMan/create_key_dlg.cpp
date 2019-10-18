#include "create_key_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"


static QStringList sMechList = {
    "CKM_AES_KEY_GEN", "CKM_DES_KEY_GEN", "CKM_DES3_KEY_GEN", "CKM_GENERIC_SECRET_KEY_GEN"
};

static QStringList sFalseTrue = { "false", "true" };

static QStringList sKeyList = { "String", "Hex", "Base64" };


CreateKeyDlg::CreateKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();
}

CreateKeyDlg::~CreateKeyDlg()
{

}


void CreateKeyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void CreateKeyDlg::showEvent(QShowEvent* event )
{
    initialize();
}

void CreateKeyDlg::initialize()
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

void CreateKeyDlg::initAttributes()
{
    mMechCombo->addItems(sMechList);
    mKeyCombo->addItems(sKeyList);

    mPrivateCombo->addItems(sFalseTrue);
    mSensitiveCombo->addItems(sFalseTrue);
    mWrapCombo->addItems(sFalseTrue);
    mUnwrapCombo->addItems(sFalseTrue);
    mEncryptCombo->addItems(sFalseTrue);
    mDecryptCombo->addItems(sFalseTrue);
    mModifiableCombo->addItems(sFalseTrue);
    mSignCombo->addItems(sFalseTrue);
    mVerifyCombo->addItems(sFalseTrue);
    mTokenCombo->addItems(sFalseTrue);
}

void CreateKeyDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mSignCombo->setEnabled(mSignCheck->isChecked());
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void CreateKeyDlg::connectAttributes()
{
    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickSensitive()));
    connect( mWrapCheck, SIGNAL(clicked()), this, SLOT(clickWrap()));
    connect( mUnwrapCheck, SIGNAL(clicked()), this, SLOT(clickUnwrap()));
    connect( mEncryptCheck, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mDecryptCheck, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mSignCheck, SIGNAL(clicked()), this, SLOT(clickSign()));
    connect( mVerifyCheck, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
}

void CreateKeyDlg::accept()
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(index);
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = 0;

    hSession = slotInfo.getSessionHandle();

    int nKeyPos = mMechCombo->currentIndex();
    keyType = JS_PKCS11_GetCKKType( sMechList.at(nKeyPos).toStdString().c_str());


    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strKey = mKeyText->text();
    BIN binKey = {0,0};

    if( mKeyCombo->currentIndex() == 0 )
        JS_BIN_set( &binKey, (unsigned char *)strKey.toStdString().c_str(), strKey.length() );
    else if( mKeyCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    else if( mKeyCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strKey.toStdString().c_str(), &binKey );

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = binKey.pVal;
    sTemplate[uCount].ulValueLen = binKey.nLen;
    uCount++;

    if( mDecryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DECRYPT;
        sTemplate[uCount].pValue = ( mDecryptCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mSensitiveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SENSITIVE;
        sTemplate[uCount].pValue = ( mSensitiveCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mSignCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN;
        sTemplate[uCount].pValue = ( mSignCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mUnwrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_UNWRAP;
        sTemplate[uCount].pValue = ( mUnwrapCombo->currentIndex() ? &bTrue : &bFalse );
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


    CK_OBJECT_CLASS hObject = 0;

    rv = JS_PKCS11_CreateObject( p11_ctx, hSession, sTemplate, uCount, &hObject );
    if( rv != CKR_OK )
    {
        return;
    }

    QDialog::accept();
}

void CreateKeyDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void CreateKeyDlg::clickSensitive()
{
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
}

void CreateKeyDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void CreateKeyDlg::clickUnwrap()
{
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
}

void CreateKeyDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void CreateKeyDlg::clickDecrypt()
{
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
}

void CreateKeyDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void CreateKeyDlg::clickSign()
{
    mSignCombo->setEnabled(mSignCheck->isChecked());
}
void CreateKeyDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}
void CreateKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}
