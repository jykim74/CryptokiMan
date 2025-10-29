/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "man_applet.h"
#include "mainwindow.h"
#include "gen_key_pair_dlg.h"
#include "js_pkcs11.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "js_pki_raw.h"
#include "common.h"
#include "cryptoki_api.h"
#include "mech_mgr.h"
#include "settings_mgr.h"
#include "export_dlg.h"
#include "thread_work_dlg.h"

static QStringList sMechGenKeyPairList;
static QStringList sDH_GList = { "02", "05" };


static QStringList sFalseTrue = { "false", "true" };

GenKeyPairDlg::GenKeyPairDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);


    initUI();

    initAttributes();
    setAttributes();
    connectAttributes();

    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));
    connect( mGenDHParamBtn, SIGNAL(clicked()), this, SLOT(clickGenDHParam()));
    connect( mDH_PText, SIGNAL(textChanged()), this, SLOT(changeDH_P()));
    connect( mExportDHParamBtn, SIGNAL(clicked()), this, SLOT(clickExportDHParam()));
    connect( mImpoortDHParamBtn, SIGNAL(clicked()), this, SLOT(clickImportDHParam()));
    connect( mDHClearParamBtn, SIGNAL(clicked()), this, SLOT(clickClearDHParam()));

    connect( mPubExponentText, SIGNAL(textChanged(QString)), this, SLOT(changePubExponent()));

    connect( mDSA_GText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_G()));
    connect( mDSA_PText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_P()));
    connect( mDSA_QText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_Q()));

    connect( mDSAGenParamBtn, SIGNAL(clicked()), this, SLOT(clickGenDSAParam()));
    connect( mDSAClearParamBtn, SIGNAL(clicked()), this, SLOT(clickClearDSAParam()));

    initialize();
    setDefaults();
    tabWidget->setCurrentIndex(0);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mDSATab->layout()->setSpacing(5);
    mDSATab->layout()->setMargin(5);
    mDHTab->layout()->setSpacing(5);
    mDHTab->layout()->setMargin(5);

    mFirstTab->layout()->setSpacing(5);
    mFirstTab->layout()->setMargin(5);
    mSecondTab->layout()->setSpacing(5);
    mSecondTab->layout()->setMargin(5);
    mThirdTab->layout()->setSpacing(5);
    mThirdTab->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

GenKeyPairDlg::~GenKeyPairDlg()
{

}

void GenKeyPairDlg::setSlotIndex(int index)
{
    slot_index_ = index;
    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    if( index >= 0 )
    {
        slot_info_ = slot_infos.at(slot_index_);
        mSlotNameText->setText( slot_info_.getDesc() );
    }

    mSlotIDText->setText( QString( "%1").arg(slot_info_.getSlotID()));
    mSessionText->setText( QString("%1").arg(slot_info_.getSessionHandle()));
    mLoginText->setText( slot_info_.getLogin() ? "YES" : "NO" );
}

void GenKeyPairDlg::initUI()
{
    if( manApplet->isLicense() )
    {
        if( manApplet->settingsMgr()->useDeviceMech() )
        {
            sMechGenKeyPairList = manApplet->mechMgr()->getGenerateKeyPairList();
        }
        else
        {
            sMechGenKeyPairList = kMechGenKeyPairList;
        }
    }
    else
    {
        sMechGenKeyPairList = kMechGenKeyPairList;
    }


    mMechCombo->addItems( sMechGenKeyPairList );

    mOptionCombo->addItems( kRSAOptionList );

    mDH_GCombo->addItems( sDH_GList );
    mParamTab->setDisabled(true);

    mPubLabelText->setPlaceholderText( tr( "String value" ));
    mPubIDText->setPlaceholderText( tr("Hex value" ));
    mPubSubjectText->setPlaceholderText( tr("Hex value" ));
    mPubExponentText->setPlaceholderText( tr("Hex value" ));

    mPriLabelText->setPlaceholderText( tr( "String value" ));
    mPriIDText->setPlaceholderText( tr("Hex value" ));
    mPriSubjectText->setPlaceholderText( tr("Hex value" ));
    mPriPubKeyInfoText->setPlaceholderText( tr("Hex value" ));
}

void GenKeyPairDlg::initialize()
{
    mechChanged(0);
}

void GenKeyPairDlg::initAttributes()
{
    mPriSubjectTypeCombo->addItems( kDNTypeList );

    mPriPrivateCombo->addItems( sFalseTrue );
    mPriPrivateCombo->setCurrentIndex(1);

    mPriDecryptCombo->addItems( sFalseTrue );
    mPriDecryptCombo->setCurrentIndex(1);

    mPriSignCombo->addItems( sFalseTrue );
    mPriSignCombo->setCurrentIndex(1);

    mPriSignRecoverCombo->addItems(sFalseTrue);
    mPriSignRecoverCombo->setCurrentIndex(1);

    mPriUnwrapCombo->addItems( sFalseTrue );
    mPriUnwrapCombo->setCurrentIndex(1);

    mPriModifiableCombo->addItems( sFalseTrue );
    mPriModifiableCombo->setCurrentIndex(1);

    mPriCopyableCombo->addItems(sFalseTrue);
    mPriCopyableCombo->setCurrentIndex(1);

    mPriDestroyableCombo->addItems(sFalseTrue);
    mPriDestroyableCombo->setCurrentIndex(1);

    mPriSensitiveCombo->addItems( sFalseTrue );
    mPriSensitiveCombo->setCurrentIndex(1);

    mPriDeriveCombo->addItems( sFalseTrue );
    mPriDeriveCombo->setCurrentIndex(1);

    mPriExtractableCombo->addItems( sFalseTrue );
    mPriExtractableCombo->setCurrentIndex(1);

    mPriTokenCombo->addItems( sFalseTrue );
    mPriTokenCombo->setCurrentIndex(1);

    mPubSubjectTypeCombo->addItems( kDNTypeList );

    mPubPrivateCombo->addItems( sFalseTrue );
    mPubPrivateCombo->setCurrentIndex(1);

    mPubEncryptCombo->addItems( sFalseTrue );
    mPubEncryptCombo->setCurrentIndex(1);

    mPubWrapCombo->addItems( sFalseTrue );
    mPubWrapCombo->setCurrentIndex(1);

    mPubVerifyCombo->addItems( sFalseTrue );
    mPubVerifyCombo->setCurrentIndex(1);

    mPubVerifyRecoverCombo->addItems(sFalseTrue);
    mPubVerifyRecoverCombo->setCurrentIndex(1);

    mPubDeriveCombo->addItems( sFalseTrue );
    mPubDeriveCombo->setCurrentIndex(1);

    mPubModifiableCombo->addItems( sFalseTrue );
    mPubModifiableCombo->setCurrentIndex(1);

    mPubCopyableCombo->addItems(sFalseTrue);
    mPubCopyableCombo->setCurrentIndex(1);

    mPubDestroyableCombo->addItems(sFalseTrue);
    mPubDestroyableCombo->setCurrentIndex(1);

    mPubTokenCombo->addItems( sFalseTrue );
    mPubTokenCombo->setCurrentIndex(1);

    mPubTrustedCombo->addItems( sFalseTrue );
    mPubTrustedCombo->setCurrentIndex(1);

    QDate nowDate = QDate::currentDate();
    mPubStartDateEdit->setDate(nowDate);
    mPubEndDateEdit->setDate(nowDate);
    mPriStartDateEdit->setDate(nowDate);
    mPriEndDateEdit->setDate(nowDate);
}

void GenKeyPairDlg::setAttributes()
{
    mPriPrivateCombo->setEnabled( mPriPrivateCheck->isChecked() );
    mPriDecryptCombo->setEnabled( mPriDecryptCheck->isChecked() );
    mPriSignCombo->setEnabled( mPriSignCheck->isChecked() );
    mPriSignRecoverCombo->setEnabled( mPriSignRecoverCheck->isChecked() );
    mPriUnwrapCombo->setEnabled( mPriUnwrapCheck->isChecked() );
    mPriModifiableCombo->setEnabled( mPriModifiableCheck->isChecked() );
    mPriCopyableCombo->setEnabled(mPriCopyableCheck->isChecked());
    mPriDestroyableCombo->setEnabled(mPriDestroyableCheck->isChecked());
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
    mPubCopyableCombo->setEnabled(mPubCopyableCheck->isChecked());
    mPubDestroyableCombo->setEnabled(mPubDestroyableCheck->isChecked());
    mPubTokenCombo->setEnabled( mPubTokenCheck->isChecked() );
    mPubTrustedCombo->setEnabled( mPubTrustedCheck->isChecked() );
    mPubStartDateEdit->setEnabled( mPubStartDateCheck->isChecked() );
    mPubEndDateEdit->setEnabled( mPubEndDateCheck->isChecked() );
}

void GenKeyPairDlg::connectAttributes()
{
    connect( mPubSameLabelBtn, SIGNAL(clicked()), this, SLOT(clickPubSameLabel()));
    connect( mPriSameLabelBtn, SIGNAL(clicked()), this, SLOT(clickPriSameLabel()));

    connect( mPriUseSKICheck, SIGNAL(clicked()), this, SLOT(clickPriUseSKI()));
    connect( mPriUseSPKICheck, SIGNAL(clicked()), this, SLOT(clickPriUseSPKI()));

    connect( mPriPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPriPrivate()));
    connect( mPriDecryptCheck, SIGNAL(clicked()), this, SLOT(clickPriDecrypt()));
    connect( mPriSignCheck, SIGNAL(clicked()), this, SLOT(clickPriSign()));
    connect( mPriSignRecoverCheck, SIGNAL(clicked()), this, SLOT(clickPriSignRecover()));
    connect( mPriUnwrapCheck, SIGNAL(clicked()), this, SLOT(clickPriUnwrap()));
    connect( mPriModifiableCheck, SIGNAL(clicked()), this, SLOT(clickPriModifiable()));
    connect( mPriCopyableCheck, SIGNAL(clicked()), this, SLOT(clickPriCopyable()));
    connect( mPriDestroyableCheck, SIGNAL(clicked()), this, SLOT(clickPriDestroyable()));
    connect( mPriSensitiveCheck, SIGNAL(clicked()), this, SLOT(clickPriSensitive()));
    connect( mPriDeriveCheck, SIGNAL(clicked()), this, SLOT(clickPriDerive()));
    connect( mPriExtractableCheck, SIGNAL(clicked()), this, SLOT(clickPriExtractable()));
    connect( mPriTokenCheck, SIGNAL(clicked()), this, SLOT(clickPriToken()));
    connect( mPriStartDateCheck, SIGNAL(clicked()), this, SLOT(clickPriStartDate()));
    connect( mPriEndDateCheck, SIGNAL(clicked()), this, SLOT(clickPriEndDate()));

    connect( mPubUseSKICheck, SIGNAL(clicked()), this, SLOT(clickPubUseSKI()));

    connect( mPubPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPubPrivate()));
    connect( mPubEncryptCheck, SIGNAL(clicked()), this, SLOT(clickPubEncrypt()));
    connect( mPubWrapCheck, SIGNAL(clicked()), this, SLOT(clickPubWrap()));
    connect( mPubVerifyCheck, SIGNAL(clicked()), this, SLOT(clickPubVerify()));
    connect( mPubVerifyRecoverCheck, SIGNAL(clicked()), this, SLOT(clickPubVerifyRecover()));
    connect( mPubDeriveCheck, SIGNAL(clicked()), this, SLOT(clickPubDerive()));
    connect( mPubModifiableCheck, SIGNAL(clicked()), this, SLOT(clickPubModifiable()));
    connect( mPubCopyableCheck, SIGNAL(clicked()), this, SLOT(clickPubCopyable()));
    connect( mPubDestroyableCheck, SIGNAL(clicked()), this, SLOT(clickPubDestroyable()));
    connect( mPubTokenCheck, SIGNAL(clicked()), this, SLOT(clickPubToken()));
    connect( mPubTrustedCheck, SIGNAL(clicked()), this, SLOT(clickPubTrusted()));
    connect( mPubStartDateCheck, SIGNAL(clicked()), this, SLOT(clickPubStartDate()));
    connect( mPubEndDateCheck, SIGNAL(clicked()), this, SLOT(clickPubEndDate()));
}

void GenKeyPairDlg::accept()
{
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();
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

    QString strMech = mMechCombo->currentText();

    if( strMech == "CKM_RSA_PKCS_KEY_PAIR_GEN" )
    {
        stMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        keyType = CKK_RSA;
    }
    else if( strMech == "CKM_EC_KEY_PAIR_GEN" || strMech == "CKM_ECDSA_KEY_PAIR_GEN" )
    {
        stMech.mechanism = CKM_ECDSA_KEY_PAIR_GEN;
        keyType = CKK_ECDSA;
    }
    else if( strMech == "CKM_DH_PKCS_KEY_PAIR_GEN" )
    {
        stMech.mechanism = CKM_DH_PKCS_KEY_PAIR_GEN;
        keyType = CKK_DH;
    }
    else if( strMech == "CKM_DSA_KEY_PAIR_GEN" )
    {
        stMech.mechanism = CKM_DSA_KEY_PAIR_GEN;
        keyType = CKK_DSA;
    }
    else if( strMech == "CKM_EC_EDWARDS_KEY_PAIR_GEN" )
    {
        stMech.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;
        keyType = CKK_EC_EDWARDS;
    }
    else
    {
        manApplet->elog( QString( "Invalid Mechanism:%1").arg(strMech));
        return;
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

    BIN binDH_G = {0,0};
    BIN binDH_P = {0,0};

    BIN binDSA_P = {0,0};
    BIN binDSA_Q = {0,0};
    BIN binDSA_G = {0,0};

    CK_ULONG uModulusBits = 0;
    int nSelOption = mOptionCombo->currentIndex();

    if( strMech == "CKM_RSA_PKCS_KEY_PAIR_GEN" )
    {
        uModulusBits = kRSAOptionList.at(nSelOption).toInt();
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
    else if( strMech == "CKM_EC_KEY_PAIR_GEN" || strMech == "CKM_ECDSA_KEY_PAIR_GEN" )
    {
        char sPararmHex[256];
        const char *pCurveName = kECDSAOptionList.at(nSelOption).toStdString().c_str();
        memset( sPararmHex, 0x00, sizeof(sPararmHex));

        // 아래 함수 시 실행이 안되지? 파악 해야 함
        JS_PKI_getHexOIDFromSN( pCurveName, sPararmHex );
        JS_BIN_decodeHex( sPararmHex, &binECParam );

        sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
        sPubTemplate[uPubCount].pValue = binECParam.pVal;
        sPubTemplate[uPubCount].ulValueLen = binECParam.nLen;
        uPubCount++;
    }
    else if( strMech == "CKM_DH_PKCS_KEY_PAIR_GEN" )
    {

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
    else if( strMech == "CKM_DSA_KEY_PAIR_GEN" )
    {
        /* DSA 알고리즘은 좀더 입력 값 확인 이 필요함 */
        /* 관련 CKA_PRIME, CKA_SUBPRIME 그리고 CKA_BASE 값 설정에 관한 */
        QString strDSA_P = mDSA_PText->text();
        QString strDSA_G = mDSA_GText->text();
        QString strDSA_Q = mDSA_QText->text();

        JS_BIN_decodeHex( strDSA_G.toStdString().c_str(), &binDSA_G );
        JS_BIN_decodeHex( strDSA_P.toStdString().c_str(), &binDSA_P );
        JS_BIN_decodeHex( strDSA_Q.toStdString().c_str(), &binDSA_Q );

        sPubTemplate[uPubCount].type = CKA_PRIME;
        sPubTemplate[uPubCount].pValue = binDSA_P.pVal;
        sPubTemplate[uPubCount].ulValueLen = binDSA_P.nLen;
        uPubCount++;

        sPubTemplate[uPubCount].type = CKA_SUBPRIME;
        sPubTemplate[uPubCount].pValue = binDSA_Q.pVal;
        sPubTemplate[uPubCount].ulValueLen = binDSA_Q.nLen;
        uPubCount++;

        sPubTemplate[uPubCount].type = CKA_BASE;
        sPubTemplate[uPubCount].pValue = binDSA_G.pVal;
        sPubTemplate[uPubCount].ulValueLen = binDSA_G.nLen;
        uPubCount++;
    }
    else if( strMech == "CKM_EC_EDWARDS_KEY_PAIR_GEN" )
    {
        char sPararmHex[256];
        QString strCurveName = mOptionCombo->currentText();

        if( strCurveName == "ED25519" )
        {
            sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
            sPubTemplate[uPubCount].pValue = kOID_X25519;
            sPubTemplate[uPubCount].ulValueLen = sizeof(kOID_X25519);
            uPubCount++;
        }
        else if( strCurveName == "ED448" )
        {
            sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
            sPubTemplate[uPubCount].pValue = kOID_X448;
            sPubTemplate[uPubCount].ulValueLen = sizeof(kOID_X448);
            uPubCount++;
        }
    }

    BIN binPubLabel = {0,0};

    QString strPubLabel = mPubLabelText->text();
    if( !strPubLabel.isEmpty() )
    {
        JS_BIN_set( &binPubLabel, (unsigned char *)strPubLabel.toStdString().c_str(), strPubLabel.toUtf8().length());
        sPubTemplate[uPubCount].type = CKA_LABEL;
        sPubTemplate[uPubCount].pValue = binPubLabel.pVal;
        sPubTemplate[uPubCount].ulValueLen = binPubLabel.nLen;
        uPubCount++;
    }

    BIN binPubSubject = {0,0};
    QString strPubSubject = mPubSubjectText->text();

    if( !strPubSubject.isEmpty() )
    {
        if( mPubSubjectTypeCombo->currentText() == "Text" )
            JS_PKI_getDERFromDN( strPubSubject.toStdString().c_str(), &binPubSubject );
        else
            JS_BIN_decodeHex( strPubSubject.toStdString().c_str(), &binPubSubject );
    }

    if( binPubSubject.nLen > 0 )
    {
        sPubTemplate[uPubCount].type = CKA_SUBJECT;
        sPubTemplate[uPubCount].pValue = binPubSubject.pVal;
        sPubTemplate[uPubCount].ulValueLen = binPubSubject.nLen;
        uPubCount++;
    }

    BIN binPubID = {0,0};
    QString strPubID = mPubIDText->text();
    if( strPubID.length() > 0 ) JS_BIN_decodeHex( strPubID.toStdString().c_str(), &binPubID );

    if( binPubID.nLen > 0 )
    {
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

    if( mPubTrustedCheck->isChecked() )
    {
        sPubTemplate[uPubCount].type = CKA_TRUSTED;
        sPubTemplate[uPubCount].pValue = ( mPubTrustedCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mPubVerifyRecoverCheck->isChecked() )
    {
        sPubTemplate[uPubCount].type = CKA_VERIFY_RECOVER;
        sPubTemplate[uPubCount].pValue = (mPubVerifyRecoverCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mPubCopyableCheck->isChecked() )
    {
        sPubTemplate[uPubCount].type = CKA_COPYABLE;
        sPubTemplate[uPubCount].pValue = ( mPubCopyableCombo->currentIndex() ? &bTrue : &bFalse );
        sPubTemplate[uPubCount].ulValueLen = sizeof(CK_BBOOL);
        uPubCount++;
    }

    if( mPubDestroyableCheck->isChecked() )
    {
        sPubTemplate[uPubCount].type = CKA_DESTROYABLE;
        sPubTemplate[uPubCount].pValue = ( mPubDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
        sPubTemplate[uPubCount].ulValueLen = sizeof(CK_BBOOL);
        uPubCount++;
    }

    if( mPubStartDateCheck->isChecked() )
    {
        getQDateToCKDate( mPubStartDateEdit->date(), &sPubStart );
        sPubTemplate[uPubCount].type = CKA_START_DATE;
        sPubTemplate[uPubCount].pValue = &sPubStart;
        sPubTemplate[uPubCount].ulValueLen = sizeof(sPubStart);
        uPubCount++;
    }

    if( mPubEndDateCheck->isChecked() )
    {
        getQDateToCKDate( mPubEndDateEdit->date(), &sPubEnd );
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
        JS_BIN_set( &binPriLabel, (unsigned char *)strPriLabel.toStdString().c_str(), strPriLabel.toUtf8().length());
        sPriTemplate[uPriCount].type = CKA_LABEL;
        sPriTemplate[uPriCount].pValue = binPriLabel.pVal;
        sPriTemplate[uPriCount].ulValueLen = binPriLabel.nLen;
        uPriCount++;
    }

    BIN binPriSubject = {0,0};
    QString strPriSubject = mPriSubjectText->text();

    if( !strPriSubject.isEmpty() )
    {
        if( mPriSubjectTypeCombo->currentText() == "Text" )
            JS_PKI_getDERFromDN( strPriSubject.toStdString().c_str(), &binPriSubject );
        else
            JS_BIN_decodeHex( strPriSubject.toStdString().c_str(), &binPriSubject );
    }

    if( binPriSubject.nLen > 0 )
    {
        sPriTemplate[uPriCount].type = CKA_SUBJECT;
        sPriTemplate[uPriCount].pValue = binPriSubject.pVal;
        sPriTemplate[uPriCount].ulValueLen = binPriSubject.nLen;
        uPriCount++;
    }

    BIN binPriID = {0,0};
    QString strPriID = mPriIDText->text();
    if( strPriID.length() > 0 ) JS_BIN_decodeHex( strPriID.toStdString().c_str(), &binPriID );

    if( binPriID.nLen > 0 )
    {
        sPriTemplate[uPriCount].type = CKA_ID;
        sPriTemplate[uPriCount].pValue = binPriID.pVal;
        sPriTemplate[uPriCount].ulValueLen = binPriID.nLen;
        uPriCount++;
    }

    BIN binPriPubKeyInfo = {0,0};
    QString strPriPubKeyInfo = mPriPubKeyInfoText->text();
    if( strPriPubKeyInfo.length() > 0 ) JS_BIN_decodeHex( strPriPubKeyInfo.toStdString().c_str(), &binPriPubKeyInfo );

    if( binPriPubKeyInfo.nLen > 0 )
    {
        sPriTemplate[uPriCount].type = CKA_PUBLIC_KEY_INFO;
        sPriTemplate[uPriCount].pValue = binPriPubKeyInfo.pVal;
        sPriTemplate[uPriCount].ulValueLen = binPriPubKeyInfo.nLen;
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

    if( mPriCopyableCheck->isChecked() )
    {
        sPriTemplate[uPriCount].type = CKA_COPYABLE;
        sPriTemplate[uPriCount].pValue = ( mPriCopyableCombo->currentIndex() ? &bTrue : &bFalse );
        sPriTemplate[uPriCount].ulValueLen = sizeof(CK_BBOOL);
        uPriCount++;
    }

    if( mPriDestroyableCheck->isChecked() )
    {
        sPriTemplate[uPriCount].type = CKA_DESTROYABLE;
        sPriTemplate[uPriCount].pValue = ( mPriDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
        sPriTemplate[uPriCount].ulValueLen = sizeof(CK_BBOOL);
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

    if( mPriSignRecoverCheck->isChecked() )
    {
        sPriTemplate[uPriCount].type = CKA_SIGN_RECOVER;
        sPriTemplate[uPriCount].pValue = (mPriSignRecoverCombo->currentIndex() ? &bTrue : &bFalse );
        sPriTemplate[uPriCount].ulValueLen = sizeof( CK_BBOOL );
        uPriCount++;
    }

    if( mPriStartDateCheck->isChecked() )
    {
        getQDateToCKDate( mPriStartDateEdit->date(), &sPriStart );
        sPriTemplate[uPriCount].type = CKA_START_DATE;
        sPriTemplate[uPriCount].pValue = &sPriStart;
        sPriTemplate[uPriCount].ulValueLen = sizeof(sPriStart);
        uPriCount++;
    }

    if( mPriEndDateCheck->isChecked() )
    {
        getQDateToCKDate( mPriEndDateEdit->date(), &sPriEnd );
        sPriTemplate[uPriCount].type = CKA_END_DATE;
        sPriTemplate[uPriCount].pValue = &sPriEnd;
        sPriTemplate[uPriCount].ulValueLen = sizeof(sPriEnd);
        uPriCount++;
    }

    rv = manApplet->cryptokiAPI()->GenerateKeyPair( hSession, &stMech, sPubTemplate, uPubCount, sPriTemplate, uPriCount, &uPubHandle, &uPriHandle );

    JS_BIN_reset( &binExponent );
    JS_BIN_reset( &binECParam );
    JS_BIN_reset( &binDH_G );
    JS_BIN_reset( &binDH_P );
    JS_BIN_reset( &binPubLabel );
    JS_BIN_reset( &binPubSubject );
    JS_BIN_reset( &binPubID );
    JS_BIN_reset( &binPriLabel );
    JS_BIN_reset( &binPriSubject );
    JS_BIN_reset( &binPriID );
    JS_BIN_reset( &binPriPubKeyInfo );
    JS_BIN_reset( &binDSA_G );
    JS_BIN_reset( &binDSA_P );
    JS_BIN_reset( &binDSA_Q );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "GenerateKeyPair execution failure [%1]").arg(JS_PKCS11_GetErrorMsg( rv )), this );
        return;
    }

    if( mPriUseSKICheck->isChecked() || mPubUseSKICheck->isChecked() || mPriUseSPKICheck->isChecked() )
    {
        if( keyType == CKK_DH )
        {
            manApplet->wlog( "DH algorithm does not support 'Use SKI or Use SPKI' option" );
        }
        else
        {
            rv = setSKI_SPKI( hSession, keyType, uPriHandle, uPubHandle );
            if( rv != CKR_OK )
            {
                manApplet->warningBox( tr( "failure to set SKI_SPKI [%1]").arg(JS_PKCS11_GetErrorMsg( rv )), this );
                return;
            }
        }
    }

    manApplet->messageBox( tr("GenerateKeyPair execution successful"), this );
    manApplet->showTypeList( slot_index_, HM_ITEM_TYPE_PRIVATEKEY );

    QDialog::accept();
}


void GenKeyPairDlg::mechChanged(int nIndex)
{
    mOptionCombo->clear();
    QString strMech = mMechCombo->currentText();
    int uMech = JS_PKCS11_GetCKMType( strMech.toStdString().c_str() );

    mMechText->setText( QString( getMechHex(uMech )));

    mPubExponentLabel->setEnabled(false);
    mPubExponentText->setEnabled(false);
    mPubExponent10Text->setEnabled(false);

    if( strMech == "CKM_RSA_PKCS_KEY_PAIR_GEN" )
    {
        mOptionLabel->setText( QString("Key Length") );
        mOptionCombo->addItems( kRSAOptionList );
        mParamTab->setDisabled(true);
        mPubExponentLabel->setEnabled(true);
        mPubExponentText->setEnabled(true);
        mPubExponent10Text->setEnabled(true);
    }
    else if( strMech == "CKM_EC_KEY_PAIR_GEN" || strMech == "CKM_ECDSA_KEY_PAIR_GEN" )
    {
        mOptionLabel->setText( QString("NamedCurve"));
        mOptionCombo->addItems( kECDSAOptionList );
        mParamTab->setDisabled(true);
    }
    else if( strMech == "CKM_DH_PKCS_KEY_PAIR_GEN" )
    {
        mOptionLabel->setText( QString("Key Length") );
        mOptionCombo->addItems( kDHOptionList );
        mParamTab->setDisabled(false);
        mParamTab->setCurrentIndex(1);
        mParamTab->setTabEnabled(0, false);
        mParamTab->setTabEnabled(1, true);
    }
    else if( strMech == "CKM_DSA_KEY_PAIR_GEN" )
    {
        mOptionLabel->setText( QString("Key Length") );
        mOptionCombo->addItems( kDSAOptionList );
        mParamTab->setDisabled(false);
        mParamTab->setCurrentIndex(0);
        mParamTab->setTabEnabled(0, true);
        mParamTab->setTabEnabled(1, false);
    }
    else if( strMech == "CKM_EC_EDWARDS_KEY_PAIR_GEN" )
    {
        mOptionLabel->setText( QString("NamedCurve"));
        mOptionCombo->addItems( kEdDSAOptionList );
        mParamTab->setDisabled(true);
    }
}

void GenKeyPairDlg::clickPriSameLabel()
{
    mPubLabelText->setText( mPriLabelText->text() );
    manApplet->messageBox( tr( "All labels are the same"), this );
}

void GenKeyPairDlg::clickPubSameLabel()
{
    mPriLabelText->setText( mPubLabelText->text() );
    manApplet->messageBox( tr( "All labels are the same"), this );
}

void GenKeyPairDlg::clickPriUseSKI()
{
    bool bVal = mPriUseSKICheck->isChecked();
    mPriIDText->setEnabled( !bVal );
}

void GenKeyPairDlg::clickPriUseSPKI()
{
    bool bVal = mPriUseSPKICheck->isChecked();
    mPriPubKeyInfoText->setEnabled( !bVal );
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

void GenKeyPairDlg::clickPriSignRecover()
{
    mPriSignRecoverCombo->setEnabled(mPriSignRecoverCheck->isChecked());
}

void GenKeyPairDlg::clickPriUnwrap()
{
    mPriUnwrapCombo->setEnabled(mPriUnwrapCheck->isChecked());
}
void GenKeyPairDlg::clickPriModifiable()
{
    mPriModifiableCombo->setEnabled(mPriModifiableCheck->isChecked());
}

void GenKeyPairDlg::clickPriCopyable()
{
    mPriCopyableCombo->setEnabled(mPriCopyableCheck->isChecked());
}

void GenKeyPairDlg::clickPriDestroyable()
{
    mPriDestroyableCombo->setEnabled(mPriDestroyableCheck->isChecked());
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

void GenKeyPairDlg::clickPubUseSKI()
{
    bool bVal = mPubUseSKICheck->isChecked();
    mPubIDText->setEnabled( !bVal );
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

void GenKeyPairDlg::clickPubVerifyRecover()
{
    mPubVerifyRecoverCombo->setEnabled(mPubVerifyRecoverCheck->isChecked());
}

void GenKeyPairDlg::clickPubDerive()
{
    mPubDeriveCombo->setEnabled(mPubDeriveCheck->isChecked());
}
void GenKeyPairDlg::clickPubModifiable()
{
    mPubModifiableCombo->setEnabled(mPubModifiableCheck->isChecked());
}

void GenKeyPairDlg::clickPubCopyable()
{
    mPubCopyableCombo->setEnabled(mPubCopyableCheck->isChecked());
}

void GenKeyPairDlg::clickPubDestroyable()
{
    mPubDestroyableCombo->setEnabled(mPubDestroyableCheck->isChecked());
}

void GenKeyPairDlg::clickPubToken()
{
    mPubTokenCombo->setEnabled(mPubTokenCheck->isChecked());
}

void GenKeyPairDlg::clickPubTrusted()
{
    mPubTrustedCombo->setEnabled(mPubTrustedCheck->isChecked());
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
#if 0
    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binQ = {0,0};

    ret = JS_PKI_genDHParam( nLen, nG, &binP, &binG, &binQ );

    mDH_PText->setPlainText( getHexString( binP.pVal, binP.nLen ));

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binQ );
#else
    ThreadWorkDlg thWork;
    thWork.runWork( nLen, nG );
    thWork.exec();
    mDH_PText->setPlainText( thWork.getP() );
#endif
}

void GenKeyPairDlg::changeDH_P()
{
    QString strLen = getDataLenString( DATA_HEX, mDH_PText->toPlainText() );
    mDH_PLenText->setText( QString("%1").arg( strLen ));
}

void GenKeyPairDlg::clickGenDSAParam()
{
    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binQ = {0,0};

    int nKeyLen = mOptionCombo->currentText().toInt();

    JS_PKI_DSA_GenParamValue( nKeyLen, &binP, &binQ, &binG );

    mDSA_GText->setText( getHexString(binG.pVal, binG.nLen));
    mDSA_PText->setText( getHexString(binP.pVal, binP.nLen));
    mDSA_QText->setText( getHexString(binQ.pVal, binQ.nLen));

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binQ );
}

void GenKeyPairDlg::clickClearDSAParam()
{
    mDSA_GText->clear();
    mDSA_PText->clear();
    mDSA_QText->clear();
}

void GenKeyPairDlg::clickExportDHParam()
{
    int ret = 0;
    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binParam = {0,0};

    ExportDlg exportDlg;

    if( mDH_PText->toPlainText().length() < 1 )
    {
        manApplet->warningBox( tr( "Parameter value is required" ), this );
        mDH_PText->setFocus();
        return;
    }

    JS_BIN_decodeHex( mDH_PText->toPlainText().toStdString().c_str(), &binP );
    JS_BIN_decodeHex( mDH_GCombo->currentText().toStdString().c_str(), &binG );

    ret = JS_PKI_encodeDHParam( &binP, &binG, NULL, &binParam );
    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to encode DH param: %1").arg( ret ));
        goto end;
    }

    exportDlg.setDHParam( &binParam );
    exportDlg.setName( "DH_param" );
    exportDlg.exec();
end :
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binParam );
}

void GenKeyPairDlg::clickImportDHParam()
{
    int ret = 0;
    BIN binParam = {0,0};
    BIN binP = {0,0};
    BIN binG = {0,0};

    QString strPath = manApplet->curFilePath();
    QString strFileName = manApplet->findFile( this, JS_FILE_TYPE_DH_PARAM, strPath );
    if( strFileName.length() < 1 ) return;

    ret = JS_BIN_fileReadBER( strFileName.toLocal8Bit().toStdString().c_str(), &binParam );
    if( ret <= 0 )
    {
        manApplet->elog( QString( "fail to read parameters: %1" ).arg( ret ));
        goto end;
    }

    ret = JS_PKI_decodeDHParam( &binParam, &binP, &binG, NULL );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to decode DH parameters: %1").arg( ret ), this );
        goto end;
    }

    mDH_PText->setPlainText( getHexString( &binP ));
    mDH_GCombo->setCurrentText( getHexString( &binG ));

end :
    JS_BIN_reset( &binParam );
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
}

void GenKeyPairDlg::clickClearDHParam()
{
    mDH_PText->clear();
}

void GenKeyPairDlg::changePubExponent()
{
    int rv = -1;
    int nPubExt = 0;
    BIN binPubExp = {0,0};

    QString strPubExp = mPubExponentText->text();
    rv = getBINFromString( &binPubExp, DATA_HEX, strPubExp );
    FORMAT_WARN_GO(rv);

    nPubExt = JS_BIN_long( &binPubExp );
    mPubExponent10Text->setText( QString("%1").arg( nPubExt ));

end :
    JS_BIN_reset( &binPubExp );
}

void GenKeyPairDlg::changeDSA_P()
{
    QString strP = mDSA_PText->text();
    QString strLen = getDataLenString( DATA_HEX, strP );
    mDSA_PLenText->setText( QString("%1").arg(strLen));
}

void GenKeyPairDlg::changeDSA_G()
{
    QString strG = mDSA_GText->text();
    QString strLen = getDataLenString( DATA_HEX, strG );
    mDSA_GLenText->setText( QString("%1").arg(strLen));
}

void GenKeyPairDlg::changeDSA_Q()
{
    QString strQ = mDSA_QText->text();
    QString strLen = getDataLenString( DATA_HEX, strQ );
    mDSA_QLenText->setText( QString("%1").arg(strLen));
}

void GenKeyPairDlg::setDefaults()
{
    mPubLabelText->setText( "Public Label" );
    mPubExponentText->setText( "010001" );

    mPriUseSKICheck->setChecked(true);
    clickPriUseSKI();
    mPubUseSKICheck->setChecked(true);
    clickPubUseSKI();

    QDateTime nowTime;
    nowTime.setSecsSinceEpoch( time(NULL) );

    mPriStartDateEdit->setDate( nowTime.date() );
    mPriEndDateEdit->setDate( nowTime.date() );

    mPubStartDateEdit->setDate( nowTime.date() );
    mPubEndDateEdit->setDate( nowTime.date() );
}

int GenKeyPairDlg::setSKI_SPKI( long hSession, int nKeyType, long hPri, long hPub )
{
    int rv = 0;
    BIN binPub = {0,0};
    BIN binSKI = {0,0};

    CryptokiAPI* cryptoAPI = manApplet->cryptokiAPI();
    if( cryptoAPI == NULL ) return -1;

    if( nKeyType == CKK_RSA )
    {
        char *pN = NULL;
        char *pE = NULL;
        BIN binN = {0,0};
        BIN binE = {0,0};

        rv = cryptoAPI->GetAttributeValue2( hSession, hPub, CKA_MODULUS, &binN );
        if( rv != 0 ) goto end;

        rv = cryptoAPI->GetAttributeValue2( hSession, hPub, CKA_PUBLIC_EXPONENT, &binE );
        if( rv != 0 )
        {
            JS_BIN_reset( &binN );
            goto end;
        }

        JRSAKeyVal  rsaKey;
        memset( &rsaKey, 0x00, sizeof(rsaKey));

        JS_BIN_encodeHex( &binN, &pN );
        JS_BIN_encodeHex( &binE, &pE );

        JS_PKI_setRSAKeyVal( &rsaKey, pN, pE, NULL, NULL, NULL, NULL, NULL, NULL );
        JS_PKI_encodeRSAPublicKey( &rsaKey, &binPub );

        JS_BIN_reset( &binN );
        JS_BIN_reset( &binE );
        if( pN ) JS_free( pN );
        if( pE ) JS_free( pE );
        JS_PKI_resetRSAKeyVal( &rsaKey );
    }
    else if( nKeyType == CKK_ECDSA || nKeyType == CKK_EC )
    {
        BIN binVal = {0,0};
        BIN binKey = {0,0};
        BIN binPubX = {0,0};
        BIN binPubY = {0,0};

        char *pPubX = NULL;
        char *pPubY = NULL;
        char sCurveOID[128];

        QString strParam = mOptionCombo->currentText();

        JECKeyVal   ecKey;
        memset( &ecKey, 0x00, sizeof(ecKey));
        memset( sCurveOID, 0x00, sizeof(sCurveOID));

        JS_PKI_getOIDFromSN( strParam.toStdString().c_str(), sCurveOID );

        rv = cryptoAPI->GetAttributeValue2( hSession, hPub, CKA_EC_POINT, &binVal );
        if( rv != 0 ) goto end;

        JS_BIN_set( &binKey, binVal.pVal + 3, binVal.nLen - 3 ); // 04+Len(1byte)+04 건너팀
        JS_BIN_set( &binPubX, &binKey.pVal[0], binKey.nLen/2 );
        JS_BIN_set( &binPubY, &binKey.pVal[binKey.nLen/2], binKey.nLen/2 );


        JS_BIN_encodeHex( &binPubX, &pPubX );
        JS_BIN_encodeHex( &binPubY, &pPubY );

        JS_PKI_setECKeyVal( &ecKey, sCurveOID, pPubX, pPubY, NULL );
        JS_PKI_encodeECPublicKey( &ecKey, &binPub );

        JS_BIN_reset( &binVal );
        JS_BIN_reset( &binKey );
        JS_BIN_reset( &binPubX );
        JS_BIN_reset( &binPubY );
        if( pPubX ) JS_free( pPubX );
        if( pPubY ) JS_free( pPubY );

        JS_PKI_resetECKeyVal( &ecKey );
    }
    else if( nKeyType == CKK_DSA )
    {
        char *pHexG = NULL;
        char *pHexP = NULL;
        char *pHexQ = NULL;
        char *pHexPub = NULL;

        BIN binVal = {0,0};
        BIN binP = {0,0};
        BIN binG = {0,0};
        BIN binQ = {0,0};

        JDSAKeyVal sDSAKey;
        memset( &sDSAKey, 0x00, sizeof(sDSAKey));

        rv = cryptoAPI->GetAttributeValue2( hSession, hPub, CKA_VALUE, &binVal );
        if( rv != 0 ) goto end;

        rv = cryptoAPI->GetAttributeValue2( hSession, hPub, CKA_PRIME, &binP );
        if( rv != 0 )
        {
            JS_BIN_reset( &binVal );
            goto end;
        }

        rv = cryptoAPI->GetAttributeValue2( hSession, hPub, CKA_SUBPRIME, &binQ );
        if( rv != 0 )
        {
            JS_BIN_reset( &binVal );
            JS_BIN_reset( &binP );
            goto end;
        }

        rv = cryptoAPI->GetAttributeValue2( hSession, hPub, CKA_BASE, &binG );
        if( rv != 0 )
        {
            JS_BIN_reset( &binVal );
            JS_BIN_reset( &binP );
            JS_BIN_reset( &binQ );
            goto end;
        }

        JS_BIN_encodeHex( &binP, &pHexP );
        JS_BIN_encodeHex( &binQ, &pHexQ );
        JS_BIN_encodeHex( &binG, &pHexG );
        JS_BIN_encodeHex( &binVal, &pHexPub );

        JS_PKI_setDSAKeyVal( &sDSAKey, pHexG, pHexP, pHexQ, pHexPub, NULL );
        JS_PKI_encodeDSAPublicKey( &sDSAKey, &binPub );

        if( pHexG ) JS_free( pHexG );
        if( pHexP ) JS_free( pHexP );
        if( pHexQ ) JS_free( pHexQ );
        if( pHexPub ) JS_free( pHexPub );

        JS_BIN_reset( &binVal );
        JS_BIN_reset( &binP );
        JS_BIN_reset( &binQ );
        JS_BIN_reset( &binG );

        JS_PKI_resetDSAKeyVal( &sDSAKey );
    }
    else if( nKeyType == CKK_EC_EDWARDS )
    {
        BIN binVal = {0,0};
        BIN binXY = {0,0};

        QString strOption = mOptionCombo->currentText();
        JRawKeyVal sRawKey;
        char *pPubHex = NULL;

        memset( &sRawKey, 0x00, sizeof(sRawKey));

        rv = cryptoAPI->GetAttributeValue2( hSession, hPub, CKA_EC_POINT, &binVal );
        if( rv != 0 ) goto end;

        JS_BIN_set( &binXY, &binVal.pVal[2], binVal.nLen - 2);

        JS_BIN_encodeHex( &binXY, &pPubHex );
        JS_PKI_setRawKeyVal( &sRawKey, JS_PKI_KEY_NAME_EDDSA, strOption.toStdString().c_str(), pPubHex, NULL );
        rv = JS_PKI_encodeRawPublicKey( &sRawKey, &binPub );

        JS_PKI_resetRawKeyVal( &sRawKey );
        if( pPubHex ) JS_free( pPubHex );
        JS_BIN_reset( &binVal );
        JS_BIN_reset( &binXY );
    }

    if( mPriUseSPKICheck->isChecked() )
    {
        rv = cryptoAPI->SetAttributeValue2( hSession, hPri, CKA_PUBLIC_KEY_INFO, &binPub );
        if( rv != 0 ) goto end;
    }

    JS_PKI_getKeyIdentifier( &binPub, &binSKI );

    if( mPriUseSKICheck->isChecked() )
    {
        rv = cryptoAPI->SetAttributeValue2( hSession, hPri, CKA_ID, &binSKI );
        if( rv != 0 ) goto end;
    }

    if( mPubUseSKICheck->isChecked() )
    {
        rv = cryptoAPI->SetAttributeValue2( hSession, hPub, CKA_ID, &binSKI );
        if( rv != 0 ) goto end;
    }

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binSKI );

    return rv;
}
