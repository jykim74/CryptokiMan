#include "man_applet.h"
#include "mainwindow.h"
#include "gen_key_pair_dlg.h"
#include "js_pkcs11.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "common.h"
#include "cryptoki_api.h"

static QStringList sMechList = { "RSA", "ECC", "DH" };
static QStringList sRSAOptionList = { "1024", "2048", "3096", "4082" };
static QStringList sDHOptionList = { "512", "1024", "2048" };
static QStringList sDH_GList = { "02", "05" };


static QStringList sFalseTrue = { "false", "true" };

GenKeyPairDlg::GenKeyPairDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));
    connect( mGenDHParamBtn, SIGNAL(clicked()), this, SLOT(clickGenDHParam()));
    connect( mDH_PText, SIGNAL(textChanged()), this, SLOT(changeDH_P()));

    initialize();
    setDefaults();
    tabWidget->setCurrentIndex(0);
}

GenKeyPairDlg::~GenKeyPairDlg()
{

}

void GenKeyPairDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex( index );
}


void GenKeyPairDlg::initialize()
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

void GenKeyPairDlg::initAttributes()
{
    mMechCombo->addItems( sMechList );

    mOptionCombo->addItems( sRSAOptionList );
    mOptionCombo->setEditable( true );

    mDH_GCombo->addItems( sDH_GList );
    mDHParamGroup->setDisabled(true);

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

void GenKeyPairDlg::setAttributes()
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
}

void GenKeyPairDlg::connectAttributes()
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
}

void GenKeyPairDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();
    int rv = -1;


    CK_MECHANISM stMech;
    CK_ULONG uPubCount = 0;
    CK_ATTRIBUTE sPubTemplate[20];
    CK_ULONG uPriCount = 0;
    CK_ATTRIBUTE sPriTemplate[20];

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS priClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType;

    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_DATE sPriStart;
    CK_DATE sPriEnd;
    CK_DATE sPubStart;
    CK_DATE sPubEnd;

    CK_OBJECT_HANDLE uPubHandle = -1;
    CK_OBJECT_HANDLE uPriHandle = -1;

    memset( &stMech, 0x00, sizeof(stMech) );
    memset( &sPriStart, 0x00, sizeof(sPriStart));
    memset( &sPriEnd, 0x00, sizeof(sPriEnd));
    memset( &sPubStart, 0x00, sizeof(sPubStart));
    memset( &sPubEnd, 0x00, sizeof(sPubEnd));

    int iSelMech = mMechCombo->currentIndex();

    if( iSelMech == 0 )
    {
        stMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        keyType = CKK_RSA;
    }
    else if( iSelMech == 1 )
    {
        stMech.mechanism = CKM_ECDSA_KEY_PAIR_GEN;
        keyType = CKK_ECDSA;
    }
    else if( iSelMech == 2 )
    {
        stMech.mechanism = CKM_DH_PKCS_KEY_PAIR_GEN;
        keyType = CKK_DH;
    }

    sPubTemplate[uPubCount].type = CKA_CLASS;
    sPubTemplate[uPubCount].pValue = &pubClass;
    sPubTemplate[uPubCount].ulValueLen = sizeof(pubClass);
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_KEY_TYPE;
    sPubTemplate[uPubCount].pValue = &keyType;
    sPubTemplate[uPubCount].ulValueLen = sizeof(keyType);
    uPubCount++;


    BIN binExponent = {0,0};
    BIN binECParam = {0,0};

    CK_ULONG uModulusBits = 0;
    int nSelOption = mOptionCombo->currentIndex();

    if( iSelMech == 0 )
    {
        uModulusBits = sRSAOptionList.at(nSelOption).toInt();
        sPubTemplate[uPubCount].type = CKA_MODULUS_BITS;
        sPubTemplate[uPubCount].pValue = &uModulusBits;
        sPubTemplate[uPubCount].ulValueLen = sizeof( uModulusBits );
        uPubCount++;

        QString strPubExponent = mPubExponentText->text();

        if( !strPubExponent.isEmpty() )
        {
            JS_BIN_decodeHex( strPubExponent.toStdString().c_str(), &binExponent );
            sPubTemplate[uPubCount].type = CKA_PUBLIC_EXPONENT;
            sPubTemplate[uPubCount].pValue = binExponent.pVal;
            sPubTemplate[uPubCount].ulValueLen = binExponent.nLen;
            uPubCount++;
        }
    }
    else if( iSelMech == 1 )
    {
        char sPararmHex[256];
        const char *pCurveName = kECCOptionList.at(nSelOption).toStdString().c_str();
        memset( sPararmHex, 0x00, sizeof(sPararmHex));

        // 아래 함수 시 실행이 안되지? 파악 해야 함
        JS_PKI_getHexOIDFromSN( pCurveName, sPararmHex );
        JS_BIN_decodeHex( sPararmHex, &binECParam );

        sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
        sPubTemplate[uPubCount].pValue = binECParam.pVal;
        sPubTemplate[uPubCount].ulValueLen = binECParam.nLen;
        uPubCount++;
    }
    else if( iSelMech == 2 )
    {
        BIN binDH_G = {0,0};
        BIN binDH_P = {0,0};

        QString strDH_P = mDH_PText->toPlainText();
        QString strDH_G = mDH_GCombo->currentText();

        JS_BIN_decodeHex( strDH_P.toStdString().c_str(), &binDH_P );
        JS_BIN_decodeHex( strDH_G.toStdString().c_str(), &binDH_G );

        sPubTemplate[uPubCount].type = CKA_PRIME;
        sPubTemplate[uPubCount].pValue = binDH_P.pVal;
        sPubTemplate[uPubCount].ulValueLen = binDH_P.nLen;
        uPubCount++;

        sPubTemplate[uPubCount].type = CKA_BASE;
        sPubTemplate[uPubCount].pValue = binDH_G.pVal;
        sPubTemplate[uPubCount].ulValueLen = binDH_G.nLen;
        uPubCount++;
    }

    BIN binPubLabel = {0,0};

    QString strPubLabel = mPubLabelText->text();
    if( !strPubLabel.isEmpty() )
    {
        JS_BIN_set( &binPubLabel, (unsigned char *)strPubLabel.toStdString().c_str(), strPubLabel.length());
        sPubTemplate[uPubCount].type = CKA_LABEL;
        sPubTemplate[uPubCount].pValue = binPubLabel.pVal;
        sPubTemplate[uPubCount].ulValueLen = binPubLabel.nLen;
        uPubCount++;
    }

    BIN binPubID = {0,0};
    QString strPubID = mPubIDText->text();
    if( !strPubID.isEmpty() )
    {
        JS_BIN_set( &binPubID, (unsigned char *)strPubID.toStdString().c_str(), strPubID.length());
        sPubTemplate[uPubCount].type = CKA_ID;
        sPubTemplate[uPubCount].pValue = binPubID.pVal;
        sPubTemplate[uPubCount].ulValueLen = binPubID.nLen;
        uPubCount++;
    }

    if( mPubTokenCheck->isChecked() )
    {
        sPubTemplate[uPubCount].type = CKA_TOKEN;
        sPubTemplate[uPubCount].pValue = ( mPubTokenCombo->currentIndex() ? &bTrue : &bFalse );
        sPubTemplate[uPubCount].ulValueLen = sizeof(CK_BBOOL);
        uPubCount++;
    }

    if( mPubPrivateCheck->isChecked() )
    {
        sPubTemplate[uPubCount].type = CKA_PRIVATE;
        sPubTemplate[uPubCount].pValue = (mPubPrivateCombo->currentIndex() ? &bTrue : &bFalse );
        sPubTemplate[uPubCount].ulValueLen = sizeof(CK_BBOOL);
        uPubCount++;
    }

    if( mPubEncryptCheck->isChecked() )
    {
        sPubTemplate[uPubCount].type = CKA_ENCRYPT;
        sPubTemplate[uPubCount].pValue = (mPubEncryptCombo->currentIndex() ? &bTrue : &bFalse );
        sPubTemplate[uPubCount].ulValueLen = sizeof(CK_BBOOL);
        uPubCount++;
    }

    if( mPubWrapCheck->isChecked() )
    {
        sPubTemplate[uPubCount].type = CKA_WRAP;
        sPubTemplate[uPubCount].pValue = (mPubWrapCombo->currentIndex() ? &bTrue : &bFalse );
        sPubTemplate[uPubCount].ulValueLen = sizeof(CK_BBOOL);
        uPubCount++;
    }

    if( mPubVerifyCheck->isChecked() )
    {
        sPubTemplate[uPubCount].type = CKA_VERIFY;
        sPubTemplate[uPubCount].pValue = (mPubVerifyCombo->currentIndex() ? &bTrue : &bFalse );
        sPubTemplate[uPubCount].ulValueLen = sizeof(CK_BBOOL);
        uPubCount++;
    }

    if( mPubModifiableCheck->isChecked() )
    {
        sPubTemplate[uPubCount].type = CKA_MODIFIABLE;
        sPubTemplate[uPubCount].pValue = (mPubModifiableCombo->currentIndex() ? &bTrue : &bFalse );
        sPubTemplate[uPubCount].ulValueLen = sizeof(CK_BBOOL);
        uPubCount++;
    }

    if( mPubStartDateCheck->isChecked() )
    {
        getCKDate( mPubStartDateEdit->date(), &sPubStart );
        sPubTemplate[uPubCount].type = CKA_START_DATE;
        sPubTemplate[uPubCount].pValue = &sPubStart;
        sPubTemplate[uPubCount].ulValueLen = sizeof(sPubStart);
        uPubCount++;
    }

    if( mPubEndDateCheck->isChecked() )
    {
        getCKDate( mPubEndDateEdit->date(), &sPubEnd );
        sPubTemplate[uPubCount].type = CKA_END_DATE;
        sPubTemplate[uPubCount].pValue = &sPubEnd;
        sPubTemplate[uPubCount].ulValueLen = sizeof(sPubEnd);
        uPubCount++;
    }

    sPriTemplate[uPriCount].type = CKA_CLASS;
    sPriTemplate[uPriCount].pValue = &priClass;
    sPriTemplate[uPriCount].ulValueLen = sizeof(priClass);
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_KEY_TYPE;
    sPriTemplate[uPriCount].pValue = &keyType;
    sPriTemplate[uPriCount].ulValueLen = sizeof(keyType);
    uPriCount++;

    BIN binPriLabel = {0,0};
    QString strPriLabel = mPriLabelText->text();

    if( !strPriLabel.isEmpty() )
    {
        JS_BIN_set( &binPriLabel, (unsigned char *)strPriLabel.toStdString().c_str(), strPriLabel.length());
        sPriTemplate[uPriCount].type = CKA_LABEL;
        sPriTemplate[uPriCount].pValue = binPriLabel.pVal;
        sPriTemplate[uPriCount].ulValueLen = binPriLabel.nLen;
        uPriCount++;
    }

    BIN binPriSubject = {0,0};
    QString strPriSubject = mPriSubjectText->text();

    if( !strPriSubject.isEmpty() )
    {
        JS_BIN_set( &binPriSubject, (unsigned char *)strPriSubject.toStdString().c_str(), strPriSubject.length() );
        sPriTemplate[uPriCount].type = CKA_SUBJECT;
        sPriTemplate[uPriCount].pValue = binPriLabel.pVal;
        sPriTemplate[uPriCount].ulValueLen = binPriLabel.nLen;
        uPriCount++;
    }

    BIN binPriID = {0,0};
    QString strPriID = mPriIDText->text();
    if( !strPriID.isEmpty() )
    {
        JS_BIN_set( &binPriID, (unsigned char *)strPriID.toStdString().c_str(), strPriID.length());
        sPriTemplate[uPriCount].type = CKA_ID;
        sPriTemplate[uPriCount].pValue = binPriID.pVal;
        sPriTemplate[uPriCount].ulValueLen = binPriID.nLen;
        uPriCount++;
    }

    if( mPriPrivateCheck->isChecked() )
    {
        sPriTemplate[uPriCount].type = CKA_PRIVATE;
        sPriTemplate[uPriCount].pValue = ( mPriPrivateCombo->currentIndex() ? &bTrue : &bFalse );
        sPriTemplate[uPriCount].ulValueLen = sizeof( CK_BBOOL );
        uPriCount++;
    }

    if( mPriTokenCheck->isChecked() )
    {
        sPriTemplate[uPriCount].type = CKA_TOKEN;
        sPriTemplate[uPriCount].pValue = (mPriTokenCombo->currentIndex() ? &bTrue : &bFalse );
        sPriTemplate[uPriCount].ulValueLen = sizeof( CK_BBOOL );
        uPriCount++;
    }

    if( mPriDecryptCheck->isChecked() )
    {
        sPriTemplate[uPriCount].type = CKA_DECRYPT;
        sPriTemplate[uPriCount].pValue = (mPriDecryptCombo->currentIndex() ? &bTrue : &bFalse );
        sPriTemplate[uPriCount].ulValueLen = sizeof( CK_BBOOL );
        uPriCount++;
    }

    if( mPriUnwrapCheck->isChecked() )
    {
        sPriTemplate[uPriCount].type = CKA_UNWRAP;
        sPriTemplate[uPriCount].pValue = (mPriUnwrapCombo->currentIndex() ? &bTrue : &bFalse );
        sPriTemplate[uPriCount].ulValueLen = sizeof( CK_BBOOL );
        uPriCount++;
    }

    if( mPriModifiableCheck->isChecked() )
    {
        sPriTemplate[uPriCount].type = CKA_MODIFIABLE;
        sPriTemplate[uPriCount].pValue = (mPriModifiableCombo->currentIndex() ? &bTrue : &bFalse );
        sPriTemplate[uPriCount].ulValueLen = sizeof( CK_BBOOL );
        uPriCount++;
    }

    if( mPriSensitiveCheck->isChecked() )
    {
        sPriTemplate[uPriCount].type = CKA_SENSITIVE;
        sPriTemplate[uPriCount].pValue = (mPriSensitiveCombo->currentIndex() ? &bTrue : &bFalse );
        sPriTemplate[uPriCount].ulValueLen = sizeof( CK_BBOOL );
        uPriCount++;
    }

    if( mPriDeriveCheck->isChecked() )
    {
        sPriTemplate[uPriCount].type = CKA_DERIVE;
        sPriTemplate[uPriCount].pValue = (mPriDeriveCombo->currentIndex() ? &bTrue : &bFalse );
        sPriTemplate[uPriCount].ulValueLen = sizeof( CK_BBOOL );
        uPriCount++;
    }

    if( mPriExtractableCheck->isChecked() )
    {
        sPriTemplate[uPriCount].type = CKA_EXTRACTABLE;
        sPriTemplate[uPriCount].pValue = (mPriExtractableCombo->currentIndex() ? &bTrue : &bFalse );
        sPriTemplate[uPriCount].ulValueLen = sizeof( CK_BBOOL );
        uPriCount++;
    }

    if( mPriSignCheck->isChecked() )
    {
        sPriTemplate[uPriCount].type = CKA_SIGN;
        sPriTemplate[uPriCount].pValue = (mPriSignCombo->currentIndex() ? &bTrue : &bFalse );
        sPriTemplate[uPriCount].ulValueLen = sizeof( CK_BBOOL );
        uPriCount++;
    }

    if( mPriStartDateCheck->isChecked() )
    {
        getCKDate( mPriStartDateEdit->date(), &sPriStart );
        sPriTemplate[uPriCount].type = CKA_START_DATE;
        sPriTemplate[uPriCount].pValue = &sPriStart;
        sPriTemplate[uPriCount].ulValueLen = sizeof(sPriStart);
        uPriCount++;
    }

    if( mPriEndDateCheck->isChecked() )
    {
        getCKDate( mPriEndDateEdit->date(), &sPriEnd );
        sPriTemplate[uPriCount].type = CKA_END_DATE;
        sPriTemplate[uPriCount].pValue = &sPriEnd;
        sPriTemplate[uPriCount].ulValueLen = sizeof(sPriEnd);
        uPriCount++;
    }

    rv = manApplet->cryptokiAPI()->GenerateKeyPair( hSession, &stMech, sPubTemplate, uPubCount, sPriTemplate, uPriCount, &uPubHandle, &uPriHandle );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "failure to generate key pairs(rv:%1)").arg(JS_PKCS11_GetErrorMsg( rv )), this );
        return;
    }

    manApplet->messageBox( tr("Success to generate key pairs"), this );
    manApplet->showTypeList( index, HM_ITEM_TYPE_PRIVATEKEY );

    QDialog::accept();
}

void GenKeyPairDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void GenKeyPairDlg::mechChanged(int nIndex)
{
    mOptionCombo->clear();

    if( nIndex == 0 )
    {
        mOptionLabel->setText( QString("Key Length") );
        mOptionCombo->addItems( sRSAOptionList );
        mDHParamGroup->setDisabled(true);
    }
    else if( nIndex == 1 )
    {
        mOptionLabel->setText( QString("NamedCurve"));
        mOptionCombo->addItems( kECCOptionList );
        mDHParamGroup->setDisabled(true);
    }
    else if( nIndex == 2 )
    {
        mOptionLabel->setText( QString("Key Length") );
        mOptionCombo->addItems( sDHOptionList );
        mDHParamGroup->setDisabled(false);
    }
}

void GenKeyPairDlg::clickPriPrivate()
{
    mPriPrivateCombo->setEnabled( mPriPrivateCheck->isChecked() );
}

void GenKeyPairDlg::clickPriDecrypt()
{
    mPriDecryptCombo->setEnabled( mPriDecryptCheck->isChecked() );
}

void GenKeyPairDlg::clickPriSign()
{
    mPriSignCombo->setEnabled(mPriSignCheck->isChecked());
}

void GenKeyPairDlg::clickPriUnwrap()
{
    mPriUnwrapCombo->setEnabled(mPriUnwrapCheck->isChecked());
}
void GenKeyPairDlg::clickPriModifiable()
{
    mPriModifiableCombo->setEnabled(mPriModifiableCheck->isChecked());
}
void GenKeyPairDlg::clickPriSensitive()
{
    mPriSensitiveCombo->setEnabled(mPriSensitiveCheck->isChecked());
}
void GenKeyPairDlg::clickPriDerive()
{
    mPriDeriveCombo->setEnabled(mPriDeriveCheck->isChecked());
}
void GenKeyPairDlg::clickPriExtractable()
{
    mPriExtractableCombo->setEnabled(mPriExtractableCheck->isChecked());
}
void GenKeyPairDlg::clickPriToken()
{
    mPriTokenCombo->setEnabled(mPriTokenCheck->isChecked());
}

void GenKeyPairDlg::clickPriStartDate()
{
    mPriStartDateEdit->setEnabled( mPriStartDateCheck->isChecked() );
}

void GenKeyPairDlg::clickPriEndDate()
{
    mPriEndDateEdit->setEnabled( mPriEndDateCheck->isChecked() );
}

void GenKeyPairDlg::clickPubPrivate()
{
    mPubPrivateCombo->setEnabled(mPubPrivateCheck->isChecked());
}
void GenKeyPairDlg::clickPubEncrypt()
{
    mPubEncryptCombo->setEnabled(mPubEncryptCheck->isChecked());
}
void GenKeyPairDlg::clickPubWrap()
{
    mPubWrapCombo->setEnabled(mPubWrapCheck->isChecked());
}
void GenKeyPairDlg::clickPubVerify()
{
    mPubVerifyCombo->setEnabled(mPubVerifyCheck->isChecked());
}
void GenKeyPairDlg::clickPubDerive()
{
    mPubDeriveCombo->setEnabled(mPubDeriveCheck->isChecked());
}
void GenKeyPairDlg::clickPubModifiable()
{
    mPubModifiableCombo->setEnabled(mPubModifiableCheck->isChecked());
}
void GenKeyPairDlg::clickPubToken()
{
    mPubTokenCombo->setEnabled(mPubTokenCheck->isChecked());
}

void GenKeyPairDlg::clickPubStartDate()
{
    mPubStartDateEdit->setEnabled( mPubStartDateCheck->isChecked());
}

void GenKeyPairDlg::clickPubEndDate()
{
    mPubEndDateEdit->setEnabled( mPubEncryptCheck->isChecked() );
}

void GenKeyPairDlg::clickGenDHParam()
{
    int ret = 0;
    int nG = mDH_GCombo->currentText().toInt();
    int nLen = mOptionCombo->currentText().toInt();

    BIN binP = {0,0};
    BIN binG = {0,0};

    ret = JS_PKI_genDHParam( nLen, nG, &binP, &binG );

    mDH_PText->setPlainText( getHexString( binP.pVal, binP.nLen ));

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
}

void GenKeyPairDlg::changeDH_P()
{
    int nLen = mDH_PText->toPlainText().length() / 2;

    mDH_PLenText->setText( QString("%1").arg( nLen ));
}

void GenKeyPairDlg::setDefaults()
{
    mPubLabelText->setText( "Public Label" );
    mPubExponentText->setText( "010001" );
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

    QDateTime nowTime;
    nowTime.setTime_t( time(NULL) );

    mPriStartDateEdit->setDate( nowTime.date() );
    mPriEndDateEdit->setDate( nowTime.date() );

    mPubStartDateEdit->setDate( nowTime.date() );
    mPubEndDateEdit->setDate( nowTime.date() );
}
