/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>

#include "import_cert_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "common.h"
#include "cryptoki_api.h"
#include "js_pki_tools.h"

static QStringList sFalseTrue = { "false", "true" };

ImportCertDlg::ImportCertDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initAttributes();
    setAttributes();
    connectAttributes();

    initialize();
    setDefaults();
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

ImportCertDlg::~ImportCertDlg()
{

}

void ImportCertDlg::setSlotIndex(int index)
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

void ImportCertDlg::initialize()
{
    mSubjectInCertCheck->setChecked( true );
    clickSubjectInCertCheck();

    mCertPathText->setPlaceholderText(tr("Find a certificate"));
}

void ImportCertDlg::initAttributes()
{
    mSubjectTypeCombo->addItems(kDNTypeList);

    mPrivateCombo->addItems(sFalseTrue);
    mPrivateCombo->setCurrentIndex(1);

    mModifiableCombo->addItems(sFalseTrue);
    mModifiableCombo->setCurrentIndex(1);

    mCopyableCombo->addItems(sFalseTrue);
    mCopyableCombo->setCurrentIndex(1);

    mDestroyableCombo->addItems(sFalseTrue);
    mDestroyableCombo->setCurrentIndex(1);

    mTokenCombo->addItems(sFalseTrue);
    mTokenCombo->setCurrentIndex(1);

    mTrustedCombo->addItems(sFalseTrue);
    mTrustedCombo->setCurrentIndex(1);

    QDate nowDate = QDate::currentDate();
    mStartDateEdit->setDate(nowDate);
    mEndDateEdit->setDate(nowDate);
}

void ImportCertDlg::setAttributes()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
    mStartDateEdit->setEnabled(mStartDateCheck->isChecked());
    mEndDateEdit->setEnabled(mEndDateCheck->isChecked());

}

void ImportCertDlg::connectAttributes()
{
    connect( mUseSKICheck, SIGNAL(clicked()), this, SLOT(clickUseSKI()));
    connect( mUseSPKICheck, SIGNAL(clicked()), this, SLOT(clickUseSPKI()));

    connect( mPrivateCheck, SIGNAL(clicked()), this, SLOT(clickPrivate()));
    connect( mModifiableCheck, SIGNAL(clicked()), this, SLOT(clickModifiable()));
    connect( mCopyableCheck, SIGNAL(clicked()), this, SLOT(clickCopyable()));
    connect( mDestroyableCheck, SIGNAL(clicked()), this, SLOT(clickDestroyable()));
    connect( mTokenCheck, SIGNAL(clicked()), this, SLOT(clickToken()));
    connect( mTrustedCheck, SIGNAL(clicked()), this, SLOT(clickTrusted()));
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));
    connect( mStartDateCheck, SIGNAL(clicked()), this, SLOT(clickStartDate()));
    connect( mEndDateCheck, SIGNAL(clicked()), this, SLOT(clickEndDate()));

    connect( mSubjectInCertCheck, SIGNAL(clicked()), this, SLOT(clickSubjectInCertCheck()));
}

void ImportCertDlg::accept()
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

    QString strCertPath = mCertPathText->text();
    QString strSubject;
    BIN binCert = {0,0};

    if( strCertPath.isEmpty() )
    {
        manApplet->warningBox( tr("Select a certificate file."), this );
        mCertPathText->setFocus();
        return;
    }

    rv = JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    if( rv < 0 )
    {
        manApplet->warningBox( tr( "failed to read certificate [%1]").arg( rv ), this);
        return;
    }

    BIN binSubject = {0,0};

    if( mSubjectInCertCheck->isChecked() )
    {
        JCertInfo sCertInfo;
        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        rv = JS_PKI_getCertSubjetDN( &binCert, &binSubject );
        if( rv != 0 )
        {
            manApplet->elog( QString( "failed to decode certificate [%1]" ).arg(rv) );
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
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    QString strID = mIDText->text();
    BIN binID = {0,0};
    BIN binPub = {0,0};

    if( mUseSKICheck->isChecked() )
    {
        JS_PKI_getPubKeyFromCert( &binCert, &binPub );
        JS_PKI_getKeyIdentifier( &binPub, &binID );
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

    if( mUseSPKICheck->isChecked() == false )
    {
        JS_BIN_reset( &binPub );
        QString strPubKeyInfo = mPubKeyInfoText->text();

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

    if( mCopyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_COPYABLE;
        sTemplate[uCount].pValue = ( mCopyableCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    if( mDestroyableCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_DESTROYABLE;
        sTemplate[uCount].pValue = ( mDestroyableCombo->currentIndex() ? &bTrue : &bFalse );
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

    if( mTrustedCheck->isChecked() )
    {
        sTemplate[uCount].type = CKA_TRUSTED;
        sTemplate[uCount].pValue = ( mTrustedCombo->currentIndex() ? &bTrue : &bFalse );
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;
    }

    rv = manApplet->cryptokiAPI()->CreateObject( hSession, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binSubject );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("CreateObject execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    manApplet->messageBox(tr("CreationObject execution successful"), this );
    manApplet->showTypeList( slot_index_, HM_ITEM_TYPE_CERTIFICATE );

    QDialog::accept();
}

void ImportCertDlg::clickUseSKI()
{
    bool bVal = mUseSKICheck->isChecked();
    mIDText->setEnabled(!bVal);
}

void ImportCertDlg::clickUseSPKI()
{
    bool bVal = mUseSPKICheck->isChecked();
    mPubKeyInfoText->setEnabled( !bVal );
}

void ImportCertDlg::clickPrivate()
{
    mPrivateCombo->setEnabled(mPrivateCheck->isChecked());
}

void ImportCertDlg::clickModifiable()
{
    mModifiableCombo->setEnabled(mModifiableCheck->isChecked());
}

void ImportCertDlg::clickCopyable()
{
    mCopyableCombo->setEnabled(mCopyableCheck->isChecked());
}

void ImportCertDlg::clickDestroyable()
{
    mDestroyableCombo->setEnabled(mDestroyableCheck->isChecked());
}

void ImportCertDlg::clickToken()
{
    mTokenCombo->setEnabled(mTokenCheck->isChecked());
}

void ImportCertDlg::clickTrusted()
{
    mTrustedCombo->setEnabled(mTrustedCheck->isChecked());
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
    QString strPath = manApplet->curFilePath();

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mCertPathText->setText( fileName );
}

void ImportCertDlg::clickSubjectInCertCheck()
{
    bool bVal = mSubjectInCertCheck->isChecked();

    mSubjectLabel->setEnabled( !bVal );
    mSubjectText->setEnabled( !bVal );
    mSubjectTypeCombo->setEnabled( !bVal );
}

void ImportCertDlg::setDefaults()
{
    mUseSKICheck->setChecked(true);
    clickUseSKI();
//    mUseSPKICheck->click();

    mLabelText->setText( "certificate label" );
    mIDText->setText( "01020304" );

    /*
    mTokenCheck->setChecked(true);
    mTokenCombo->setEnabled(true);
    mTokenCombo->setCurrentIndex(1);
    */

    QDateTime nowTime;
    nowTime.setSecsSinceEpoch( time(NULL) );

    mStartDateEdit->setDate( nowTime.date() );
    mEndDateEdit->setDate( nowTime.date() );
}
