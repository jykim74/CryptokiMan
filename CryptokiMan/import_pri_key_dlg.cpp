/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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
    memset( &ski_, 0x00, sizeof(ski_));
    memset( &spki_, 0x00, sizeof(spki_));

    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    initialize();
    setDefaults();

    tabWidget->setCurrentIndex(0);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mFirstTab->layout()->setSpacing(5);
    mFirstTab->layout()->setMargin(5);
    mSecondTab->layout()->setSpacing(5);
    mSecondTab->layout()->setMargin(5);
    mThirdTab->layout()->setSpacing(5);
    mThirdTab->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

ImportPriKeyDlg::~ImportPriKeyDlg()
{
    JS_BIN_reset( &ski_ );
    JS_BIN_reset( &spki_ );
}

void ImportPriKeyDlg::setSlotIndex(int index)
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

void ImportPriKeyDlg::initialize()
{
    checkSavePubKey();
    checkEncPriKey();

    mPathText->setPlaceholderText( tr( "Find a private key" ));

    mPubLabelText->setPlaceholderText( tr("String value" ));
    mPubIDText->setPlaceholderText( tr( "Hex value" ));
    mPriLabelText->setPlaceholderText( tr( "String value" ));
    mPriIDText->setPlaceholderText( tr("Hex value" ));
    mPriPubKeyInfoText->setPlaceholderText( tr("Hex value" ));
}

void ImportPriKeyDlg::initAttributes()
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

void ImportPriKeyDlg::connectAttributes()
{
    connect( mPubSameLabelBtn, SIGNAL(clicked()), this, SLOT(clickPubSameLabel()));
    connect( mPriSameLabelBtn, SIGNAL(clicked()), this, SLOT(clickPriSameLabel()));

    connect( mSavePubKeyCheck, SIGNAL(clicked()), this, SLOT(checkSavePubKey()));
    connect( mEncPriKeyCheck, SIGNAL(clicked()), this, SLOT(checkEncPriKey()));

    connect( mPriUseSKICheck, SIGNAL(clicked()), this, SLOT(clickPriUseSKI()));
    connect( mPriUseSPKICheck, SIGNAL(clicked()), this, SLOT(clickPriUseSPKI()));

    connect( mPriPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPriPrivate()));
    connect( mPriDecryptCheck, SIGNAL(clicked()), this, SLOT(clickPriDecrypt()));
    connect( mPriSignCheck, SIGNAL(clicked()), this, SLOT(clickPriSign()));
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
    connect( mPubDeriveCheck, SIGNAL(clicked()), this, SLOT(clickPubDerive()));
    connect( mPubModifiableCheck, SIGNAL(clicked()), this, SLOT(clickPubModifiable()));
    connect( mPubCopyableCheck, SIGNAL(clicked()), this, SLOT(clickPubCopyable()));
    connect( mPubDestroyableCheck, SIGNAL(clicked()), this, SLOT(clickPubDestroyable()));
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
    if( strPriPath.length() < 1 )
    {
        manApplet->warningBox( tr( "find a private key" ), this );
        mPathText->setFocus();
        return -1;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        manApplet->warningBox( tr( "failed to read private key: %1").arg( ret ), this );
        mPasswdText->setFocus();
        return  -1;
    }

    if( mEncPriKeyCheck->isChecked() )
    {
        QString strPasswd = mPasswdText->text();
        if( strPasswd.length() < 1 )
        {
            manApplet->warningBox( tr( "Enter a password"), this );
            mPasswdText->setFocus();
            ret = -1;
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
        if( ret != 0 )
        {
            manApplet->warningBox( tr( "failed to decrypt private key [%1]").arg( ret ), this );
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
    int rv = -1;
    int nKeyType = -1;

    BIN binPri = {0,0};
    BIN binPub = {0,0};

    JRSAKeyVal rsaKeyVal;
    JECKeyVal ecKeyVal;
    JDSAKeyVal dsaKeyVal;
    JRawKeyVal rawKeyVal;

    memset( &rsaKeyVal, 0x00, sizeof(JRSAKeyVal));
    memset( &ecKeyVal, 0x00, sizeof(JECKeyVal));
    memset( &dsaKeyVal, 0x00, sizeof(JDSAKeyVal));
    memset( &rawKeyVal, 0x00, sizeof(JRawKeyVal));

    rv = readPrivateKey( &binPri );
    if( rv != 0 ) return;

    nKeyType = JS_PKI_getPriKeyType( &binPri );

    rv = JS_PKI_getPubKeyFromPri( nKeyType, &binPri, &binPub );
    if( rv != 0 )
    {
        goto end;
    }

    JS_BIN_copy( &spki_, &binPub );
    JS_PKI_getKeyIdentifier( &binPub, &ski_ );



    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        rv = JS_PKI_getRSAKeyVal( &binPri, &rsaKeyVal );
        if( rv == 0 )
        {
            rv = createRSAPrivateKey( &rsaKeyVal );
            if( rv != 0 ) goto end;

            if( mSavePubKeyCheck->isChecked() )
                rv = createRSAPublicKey( &rsaKeyVal );
        }
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ECDSA )
    {
        rv = JS_PKI_getECKeyVal( &binPri, &ecKeyVal );
        if( rv == 0 )
        {
            rv = createECPrivateKey( &ecKeyVal );
            if( rv != 0 ) goto end;

            if( mSavePubKeyCheck->isChecked() )
                rv = createECPublicKey( &ecKeyVal );
        }
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_EDDSA )
    {
        rv = JS_PKI_getRawKeyVal( &binPri, &rawKeyVal );
        if( rv == 0 )
        {
            rv = createEDPrivateKey( &rawKeyVal );
            if( rv != 0 ) goto end;

            if( mSavePubKeyCheck->isChecked() )
                rv = createEDPublicKey( &rawKeyVal );
        }
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_DSA )
    {
        rv = JS_PKI_getDSAKeyVal( &binPri, &dsaKeyVal );
        if( rv == 0 )
        {
            rv = createDSAPrivateKey( &dsaKeyVal );
            if( rv != 0 ) goto end;

            if( mSavePubKeyCheck->isChecked() )
                rv = createDSAPublicKey( &dsaKeyVal );
        }
    }
    else
    {
        manApplet->elog( QString( "Key type not supported (%1)").arg(nKeyType));
        rv = -1;
        goto end;
    }

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_PKI_resetRSAKeyVal( &rsaKeyVal );
    JS_PKI_resetECKeyVal( &ecKeyVal );
    JS_PKI_resetDSAKeyVal( &dsaKeyVal );
    JS_PKI_resetRawKeyVal( &rawKeyVal );

    if( rv != 0 )
    {
        manApplet->warningBox( tr("failed to get key information."), this );
        return;
    }

    manApplet->messageBox( tr("Private key import successful"), this );
    manApplet->showTypeList( slot_index_, HM_ITEM_TYPE_PRIVATEKEY );

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

void ImportPriKeyDlg::clickPriSameLabel()
{
    mPubLabelText->setText( mPriLabelText->text() );
    manApplet->messageBox( tr( "All labels are the same"), this );
}

void ImportPriKeyDlg::clickPubSameLabel()
{
    mPriLabelText->setText( mPubLabelText->text() );
    manApplet->messageBox( tr( "All labels are the same"), this );
}


void ImportPriKeyDlg::checkSavePubKey()
{
    bool bVal = mSavePubKeyCheck->isChecked();

    tabWidget->setTabEnabled( 2, bVal );
}

void ImportPriKeyDlg::checkEncPriKey()
{
    bool bVal = mEncPriKeyCheck->isChecked();

    mPasswdLabel->setEnabled(bVal);
    mPasswdText->setEnabled(bVal);
}

void ImportPriKeyDlg::clickPriUseSKI()
{
    bool bVal = mPriUseSKICheck->isChecked();
    mPriIDText->setEnabled( !bVal );
}

void ImportPriKeyDlg::clickPriUseSPKI()
{
    bool bVal = mPriUseSPKICheck->isChecked();
    mPriPubKeyInfoText->setEnabled( !bVal );
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

void ImportPriKeyDlg::clickPriCopyable()
{
    mPriCopyableCombo->setEnabled(mPriCopyableCheck->isChecked());
}

void ImportPriKeyDlg::clickPriDestroyable()
{
    mPriDestroyableCombo->setEnabled(mPriDestroyableCheck->isChecked());
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

void ImportPriKeyDlg::clickPubUseSKI()
{
    bool bVal = mPubUseSKICheck->isChecked();
    mPubIDText->setEnabled( !bVal );
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

void ImportPriKeyDlg::clickPubCopyable()
{
    mPubCopyableCombo->setEnabled(mPubCopyableCheck->isChecked());
}

void ImportPriKeyDlg::clickPubDestroyable()
{
    mPubDestroyableCombo->setEnabled(mPubDestroyableCheck->isChecked());
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
    QString strPath;
    QString fileName = manApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mPathText->setText( fileName );
}

void ImportPriKeyDlg::setPubBoolTemplate( CK_ATTRIBUTE sTemplate[], CK_ULONG& uCount )
{
    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    //    CK_ULONG uCount = *puCount;

    if( mPubTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = ( mPubTokenCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubTrustedCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TRUSTED;
        sTemplate[uCount].pValue = ( mPubTrustedCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = ( mPubPrivateCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubEncryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_ENCRYPT;
        sTemplate[uCount].pValue = ( mPubEncryptCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubWrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_WRAP;
        sTemplate[uCount].pValue = ( mPubWrapCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubVerifyCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_VERIFY;
        sTemplate[uCount].pValue = (mPubVerifyCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubVerifyRecoverCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_VERIFY_RECOVER;
        sTemplate[uCount].pValue = (mPubVerifyRecoverCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubModifiableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPubModifiableCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        sTemplate[uCount].pValue = ( mPubCopyableCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mPubDestroyableCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubStartDateCheck->isChecked() )
    {
        getQDateToCKDate( mPubStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mPubEndDateCheck->isChecked() )
    {
        getQDateToCKDate( mPubEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }

    //    *puCount = uCount;
}

void ImportPriKeyDlg::setPriBoolTemplate( CK_ATTRIBUTE sTemplate[], CK_ULONG& uCount )
{
    CK_DATE sSDate;
    CK_DATE sEDate;

    memset( &sSDate, 0x00, sizeof(sSDate));
    memset( &sEDate, 0x00, sizeof(sEDate));

    if( mPriPrivateCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = ( mPriPrivateCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriTokenCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = (mPriTokenCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriDecryptCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DECRYPT;
        sTemplate[uCount].pValue = (mPriDecryptCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriUnwrapCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_UNWRAP;
        sTemplate[uCount].pValue = (mPriUnwrapCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriModifiableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_MODIFIABLE;
        sTemplate[uCount].pValue = (mPriModifiableCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        sTemplate[uCount].pValue = ( mPriCopyableCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPriDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mPriDestroyableCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPriSensitiveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SENSITIVE;
        sTemplate[uCount].pValue = (mPriSensitiveCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriDeriveCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DERIVE;
        sTemplate[uCount].pValue = (mPriDeriveCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriExtractableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_EXTRACTABLE;
        sTemplate[uCount].pValue = (mPriExtractableCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriSignCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN;
        sTemplate[uCount].pValue = (mPriSignCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriSignRecoverCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_SIGN_RECOVER;
        sTemplate[uCount].pValue = (mPriSignRecoverCombo->currentIndex() ? &kTrue : &kFalse );
        sTemplate[uCount].ulValueLen = sizeof( CK_BBOOL );
        uCount++;
    }

    if( mPriStartDateCheck->isChecked() )
    {
        getQDateToCKDate( mPriStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mPriEndDateCheck->isChecked() )
    {
        getQDateToCKDate( mPriEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }
}


int ImportPriKeyDlg::createRSAPublicKey( JRSAKeyVal *pRsaKeyVal )
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strSubject = mPubSubjectText->text();
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        if( mPubSubjectTypeCombo->currentText() == "Text" )
            JS_PKI_getDERFromDN( strSubject.toStdString().c_str(), &binSubject );
        else
            JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );

        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
        uCount++;
    }

    QString strID = mPubIDText->text();
    BIN binID = {0,0};

    if( mPubUseSKICheck->isChecked() )
    {
        JS_BIN_copy( &binID, &ski_ );
    }
    else
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    }

    if( binID.nLen > 0 )
    {
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

    if( mPubCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        sTemplate[uCount].pValue = ( mPubCopyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mPubDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubStartDateCheck->isChecked() )
    {
        getQDateToCKDate( mPubStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mPubEndDateCheck->isChecked() )
    {
        getQDateToCKDate( mPubEndDateEdit->date(), &sEDate );
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
        manApplet->warningBox( tr("CreateObject execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createRSAPrivateKey( JRSAKeyVal *pRsaKeyVal )
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mPriIDText->text();
    BIN binID = {0,0};

    if( mPriUseSKICheck->isChecked() )
    {
        JS_BIN_copy( &binID, &ski_ );
    }
    else
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    }

    if( binID.nLen > 0 )
    {
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    QString strPriPubKeyInfo = mPriPubKeyInfoText->text();
    BIN binPub = {0,0};

    if( mPriUseSPKICheck->isChecked() )
    {
        JS_BIN_copy( &binPub, &spki_ );
    }
    else
    {
        if( strPriPubKeyInfo.length() > 0 )
            JS_BIN_decodeHex( strPriPubKeyInfo.toStdString().c_str(), &binPub );
    }

    if( binPub.nLen > 0 )
    {
        sTemplate[uCount].type = CKA_PUBLIC_KEY_INFO;
        sTemplate[uCount].pValue = binPub.pVal;
        sTemplate[uCount].ulValueLen = binPub.nLen;
        uCount++;
    }

    QString strSubject = mPriSubjectText->text();
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        if( mPriSubjectTypeCombo->currentText() == "Text" )
            JS_PKI_getDERFromDN( strSubject.toStdString().c_str(), &binSubject );
        else
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

    if( mPriCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        sTemplate[uCount].pValue = ( mPriCopyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPriDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mPriDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
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
        getQDateToCKDate( mPriStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mPriEndDateCheck->isChecked() )
    {
        getQDateToCKDate( mPriEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binID );
    JS_BIN_reset( &binPub );
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
        manApplet->warningBox( tr("CreateObject execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createECPublicKey( JECKeyVal *pEcKeyVal )
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strSubject = mPubSubjectText->text();
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        if( mPubSubjectTypeCombo->currentText() == "Text" )
            JS_PKI_getDERFromDN( strSubject.toStdString().c_str(), &binSubject );
        else
            JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );

        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
        uCount++;
    }

    QString strID = mPubIDText->text();
    BIN binID = {0,0};

    if( mPubUseSKICheck->isChecked() )
    {
        JS_BIN_copy( &binID, &ski_ );
    }
    else
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    }

    if( binID.nLen > 0 )
    {
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

    if( mPubCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        sTemplate[uCount].pValue = ( mPubCopyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mPubDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubStartDateCheck->isChecked() )
    {
        getQDateToCKDate( mPubStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mPubEndDateCheck->isChecked() )
    {
        getQDateToCKDate( mPubEndDateEdit->date(), &sEDate );
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
        manApplet->warningBox( tr("CreateObject execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createECPrivateKey( JECKeyVal *pEcKeyVal )
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();


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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mPriIDText->text();
    BIN binID = {0,0};

    if( mPriUseSKICheck->isChecked() )
    {
        JS_BIN_copy( &binID, &ski_ );
    }
    else
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    }

    if( binID.nLen > 0 )
    {
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    QString strPriPubKeyInfo = mPriPubKeyInfoText->text();
    BIN binPub = {0,0};

    if( mPriUseSPKICheck->isChecked() )
    {
        JS_BIN_copy( &binPub, &spki_ );
    }
    else
    {
        if( strPriPubKeyInfo.length() > 0 )
            JS_BIN_decodeHex( strPriPubKeyInfo.toStdString().c_str(), &binPub );
    }

    if( binPub.nLen > 0 )
    {
        sTemplate[uCount].type = CKA_PUBLIC_KEY_INFO;
        sTemplate[uCount].pValue = binPub.pVal;
        sTemplate[uCount].ulValueLen = binPub.nLen;
        uCount++;
    }

    QString strSubject = mPriSubjectText->text();
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        if( mPriSubjectTypeCombo->currentText() == "Text" )
            JS_PKI_getDERFromDN( strSubject.toStdString().c_str(), &binSubject );
        else
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

    if( mPriCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        sTemplate[uCount].pValue = ( mPriCopyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPriDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mPriDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
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
        getQDateToCKDate( mPriStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mPriEndDateCheck->isChecked() )
    {
        getQDateToCKDate( mPriEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binID );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binECParam );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binLabel );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("CreateObject execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createEDPublicKey( JRawKeyVal *pRawKeyVal )
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = -1;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_EC_EDWARDS;

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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mPubIDText->text();
    BIN binID = {0,0};

    if( mPubUseSKICheck->isChecked() )
    {
        JS_BIN_copy( &binID, &ski_ );
    }
    else
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    }

    if( binID.nLen > 0 )
    {
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    QString strSubject = mPubSubjectText->text();
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        if( mPubSubjectTypeCombo->currentText() == "Text" )
            JS_PKI_getDERFromDN( strSubject.toStdString().c_str(), &binSubject );
        else
            JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );

        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
        uCount++;
    }

    if( strcasecmp( pRawKeyVal->pParam, JS_EDDSA_PARAM_NAME_25519 ) == 0 )
    {
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = kCurveNameX25519;
        sTemplate[uCount].ulValueLen = sizeof(kCurveNameX25519);
        uCount++;
    }
    else
    {
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = kCurveNameX448;
        sTemplate[uCount].ulValueLen = sizeof(kCurveNameX448);
        uCount++;
    }

    QString strECPoint;
    BIN binECPoint={0,0};

    strECPoint = "04";
    strECPoint += QString( "%1" ).arg( strlen( pRawKeyVal->pPub )/2, 2, 16, QLatin1Char('0'));
    strECPoint += pRawKeyVal->pPub;

    JS_BIN_decodeHex( strECPoint.toStdString().c_str(), &binECPoint );

    sTemplate[uCount].type = CKA_EC_POINT;
    sTemplate[uCount].pValue = binECPoint.pVal;
    sTemplate[uCount].ulValueLen = binECPoint.nLen;
    uCount++;

    setPubBoolTemplate( sTemplate, uCount );

    JS_BIN_reset( &binECPoint );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binID );

    return 0;
}

int ImportPriKeyDlg::createEDPrivateKey( JRawKeyVal *pRawKeyVal )
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();


    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG uCount = 0;
    CK_OBJECT_HANDLE hObject = -1;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC_EDWARDS;

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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mPriIDText->text();
    BIN binID = {0,0};

    if( mPriUseSKICheck->isChecked() )
    {
        JS_BIN_copy( &binID, &ski_ );
    }
    else
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    }

    if( binID.nLen > 0 )
    {
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    QString strPubKeyInfo = mPriPubKeyInfoText->text();
    BIN binPub = {0,0};

    if( mPriUseSPKICheck->isChecked() )
    {
        JS_BIN_copy( &binPub, &spki_ );
    }
    else
    {
        if( strPubKeyInfo.length() > 0 )
            JS_BIN_decodeHex( strPubKeyInfo.toStdString().c_str(), &binPub );
    }

    if( binPub.nLen > 0 )
    {
        sTemplate[uCount].type = CKA_PUBLIC_KEY_INFO;
        sTemplate[uCount].pValue = binPub.pVal;
        sTemplate[uCount].ulValueLen = binPub.nLen;
        uCount++;
    }

    QString strSubject = mPriSubjectText->text();;
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        if( mPriSubjectTypeCombo->currentText() == "Text" )
            JS_PKI_getDERFromDN( strSubject.toStdString().c_str(), &binSubject );
        else
            JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );

        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
        uCount++;
    }

    if( strcasecmp( pRawKeyVal->pParam, JS_EDDSA_PARAM_NAME_25519 ) == 0 )
    {
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = kCurveNameX25519;
        sTemplate[uCount].ulValueLen = sizeof(kCurveNameX25519);
        uCount++;
    }
    else
    {
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = kCurveNameX448;
        sTemplate[uCount].ulValueLen = sizeof(kCurveNameX448);
        uCount++;
    }

    BIN binValue = {0,0};
    JS_BIN_decodeHex( pRawKeyVal->pPri, &binValue );

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = binValue.pVal;
    sTemplate[uCount].ulValueLen = binValue.nLen;
    uCount++;

    setPriBoolTemplate( sTemplate, uCount );

    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binID );

    return 0;
}

int ImportPriKeyDlg::createDSAPublicKey( JDSAKeyVal *pDSAKeyVal )
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strSubject = mPubSubjectText->text();
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        if( mPubSubjectTypeCombo->currentText() == "Text" )
            JS_PKI_getDERFromDN( strSubject.toStdString().c_str(), &binSubject );
        else
            JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binSubject );

        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
        uCount++;
    }

    QString strID = mPubIDText->text();
    BIN binID = {0,0};

    if( mPubUseSKICheck->isChecked() )
    {
        JS_BIN_copy( &binID, &ski_ );
    }
    else
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    }

    if( binID.nLen > 0 )
    {
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

    if( mPubCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        sTemplate[uCount].pValue = ( mPubCopyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mPubDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPubStartDateCheck->isChecked() )
    {
        getQDateToCKDate( mPubStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mPubEndDateCheck->isChecked() )
    {
        getQDateToCKDate( mPubEndDateEdit->date(), &sEDate );
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
        manApplet->warningBox( tr("CreateObject execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        return rv;
    }

    return 0;
}

int ImportPriKeyDlg::createDSAPrivateKey( JDSAKeyVal *pDSAKeyVal )
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();


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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mPriIDText->text();
    BIN binID = {0,0};

    if( mPriUseSKICheck->isChecked() )
    {
        JS_BIN_copy( &binID, &ski_ );
    }
    else
    {
        JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    }

    if( binID.nLen > 0 )
    {
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    QString strPriPubKeyInfo = mPriPubKeyInfoText->text();
    BIN binPub = {0,0};

    if( mPriUseSPKICheck->isChecked() )
    {
        JS_BIN_copy( &binPub, &spki_ );
    }
    else
    {
        if( strPriPubKeyInfo.length() > 0 )
            JS_BIN_decodeHex( strPriPubKeyInfo.toStdString().c_str(), &binPub );
    }

    if( binPub.nLen > 0 )
    {
        sTemplate[uCount].type = CKA_PUBLIC_KEY_INFO;
        sTemplate[uCount].pValue = binPub.pVal;
        sTemplate[uCount].ulValueLen = binPub.nLen;
        uCount++;
    }

    QString strSubject;
    BIN binSubject = {0,0};

    if( !strSubject.isEmpty() )
    {
        if( mPriSubjectTypeCombo->currentText() == "Text" )
            JS_PKI_getDERFromDN( strSubject.toStdString().c_str(), &binSubject );
        else
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

    if( mPriCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        sTemplate[uCount].pValue = ( mPriCopyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mPriDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mPriDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
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
        getQDateToCKDate( mPriStartDateEdit->date(), &sSDate );
        sTemplate[uCount].type = CKA_START_DATE;
        sTemplate[uCount].pValue = &sSDate;
        sTemplate[uCount].ulValueLen = sizeof(sSDate);
        uCount++;
    }

    if( mPriEndDateCheck->isChecked() )
    {
        getQDateToCKDate( mPriEndDateEdit->date(), &sEDate );
        sTemplate[uCount].type = CKA_END_DATE;
        sTemplate[uCount].pValue = &sEDate;
        sTemplate[uCount].ulValueLen = sizeof(sEDate);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binG );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("CreateObject execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        return rv;
    }

    return 0;
}


void ImportPriKeyDlg::setDefaults()
{
    const QString strDefaultID = "0102030405060708";

    mPriUseSKICheck->setChecked(true);
    clickPriUseSKI();

//    mPriUseSPKICheck->click();

    mPubUseSKICheck->setChecked(true);
    clickPubUseSKI();

    /*
    mPubLabelText->setText( "Public Label" );
    mPubIDText->setText( strDefaultID );

    mPriLabelText->setText( "Private Label" );
    mPriIDText->setText( strDefaultID );
    */


    QDateTime nowTime;
    nowTime.setSecsSinceEpoch( time(NULL) );

    mPriStartDateEdit->setDate( nowTime.date() );
    mPriEndDateEdit->setDate( nowTime.date() );

    mPubStartDateEdit->setDate( nowTime.date() );
    mPubEndDateEdit->setDate( nowTime.date() );
}
