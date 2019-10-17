#include "gen_key_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"

static QStringList sMechList = {
    "CKM_AES_KEY_GEN", "CKM_DES_KEY_GEN", "CKM_DES3_KEY_GEN", "CKM_GENERIC_SECRET_KEY_GEN"
};

static QStringList sFalseTrue = { "false", "true" };

static QStringList sParamList = { "String", "Hex", "Base64" };

GenKeyDlg::GenKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();
}

GenKeyDlg::~GenKeyDlg()
{

}

void GenKeyDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void GenKeyDlg::showEvent(QShowEvent* event )
{
    initialize();
}

void GenKeyDlg::initialize()
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

void GenKeyDlg::initAttributes()
{
    mMechCombo->addItems(sMechList);
    mParamCombo->addItems(sParamList);

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

void GenKeyDlg::setAttributes()
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

void GenKeyDlg::connectAttributes()
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

void GenKeyDlg::accept()
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(index);
    int rv = -1;
    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = 0;
    CK_MECHANISM    sMech;

    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    hSession = slotInfo.getSessionHandle();
    memset( &sMech, 0x00, sizeof(sMech) );
    int nMechSel = mMechCombo->currentIndex();

    sMech.mechanism = JS_PKCS11_GetCKMType( sMechList.at(nMechSel).toStdString().c_str() );
    BIN binParam = {0,0};

    QString strParam = mParamText->text();
    if( !strParam.isEmpty() )
    {
        if( mParamCombo->currentIndex() == 0 )
            JS_BIN_set( &binParam, (unsigned char *)strParam.toStdString().c_str(), strParam.length() );
        else if( mParamCombo->currentIndex() == 1 )
            JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );
        else if( mParamCombo->currentIndex() == 2 )
            JS_BIN_decodeBase64( strParam.toStdString().c_str(), &binParam );

        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &keyClass;
    sTemplate[uCount].ulValueLen = sizeof(keyClass);
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

    CK_ULONG modBits = mKeySizeText->text().toLong();
    if( modBits > 0 )
    {
        sTemplate[uCount].type = CKA_VALUE_LEN;
        sTemplate[uCount].pValue = &modBits;
        sTemplate[uCount].ulValueLen = sizeof(modBits);
        uCount++;
    }

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

    rv = JS_PKCS11_GenerateKey( p11_ctx, hSession, &sMech, sTemplate, uCount, &hObject );
    if( rv != CKR_OK )
    {
        return;
    }


    QDialog::accept();
}

void GenKeyDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void GenKeyDlg::clickSensitive()
{
    mSensitiveCombo->setEnabled(mSensitiveCheck->isChecked());
}

void GenKeyDlg::clickWrap()
{
    mWrapCombo->setEnabled(mWrapCheck->isChecked());
}

void GenKeyDlg::clickUnwrap()
{
    mUnwrapCombo->setEnabled(mUnwrapCheck->isChecked());
}

void GenKeyDlg::clickEncrypt()
{
    mEncryptCombo->setEnabled(mEncryptCheck->isChecked());
}

void GenKeyDlg::clickDecrypt()
{
    mDecryptCombo->setEnabled(mDecryptCheck->isChecked());
}

void GenKeyDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void GenKeyDlg::clickSign()
{
    mSignCombo->setEnabled(mSignCheck->isChecked());
}
void GenKeyDlg::clickVerify()
{
    mVerifyCombo->setEnabled(mVerifyCheck->isChecked());
}
void GenKeyDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}
