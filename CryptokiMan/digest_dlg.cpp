/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileInfo>
#include <QDateTime>

#include "digest_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"
#include "settings_mgr.h"
#include "mech_mgr.h"
#include "digest_thread.h"
#include "hsm_man_dlg.h"

static QStringList sMechDigestList;

static QStringList sInputList = {
    "String", "Hex", "Base64"
};

DigestDlg::DigestDlg(QWidget *parent) :
    QDialog(parent)
{
    thread_ = NULL;
    update_cnt_ = 0;
    setupUi(this);

    initUI();
    initialize();
    mDigestBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mDataTab->layout()->setSpacing(5);
    mDataTab->layout()->setMargin(5);
    mFileTab->layout()->setSpacing(5);
    mFileTab->layout()->setMargin(5);

    mInputClearBtn->setFixedWidth(34);
    mOutputClearBtn->setFixedWidth(34);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

DigestDlg::~DigestDlg()
{
    if( thread_ ) delete thread_;

    if( status_type_ == STATUS_INIT || status_type_ == STATUS_UPDATE )
        clickFinal();
}

void DigestDlg::initUI()
{
    if( manApplet->settingsMgr()->useDeviceMech() )
    {
        QStringList mechList = manApplet->mechMgr()->getDigestList();
        sMechDigestList = mechList;
    }
    else
    {
        sMechDigestList = kMechDigestList;
    }

    mInputCombo->addItems( sInputList );
    mMechCombo->addItems( sMechDigestList );

    connect( mParamText, SIGNAL(textChanged(const QString)), this, SLOT(changeParam(const QString)));
    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeMech(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mSelectBtn, SIGNAL(clicked()), this, SLOT(clickSelectKey()));
    connect( mDigestKeyBtn, SIGNAL(clicked()), this, SLOT(clickDigestKey()));
    connect( mDigestBtn, SIGNAL(clicked()), this, SLOT(clickDigest()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));


    connect( mInputCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(inputChanged()));
    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged(const QString&)), this, SLOT(outputChanged()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));
    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));

    mKeyLabelText->setPlaceholderText( tr( "Select a key from HSM Man" ));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

long DigestDlg::getSessionHandle()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    return hSession;
}

void DigestDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    slot_index_ = index;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    session_ = slotInfo.getSessionHandle();
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );

    mSlotsCombo->clear();
    mSlotsCombo->addItem( slotInfo.getDesc() );
}

void DigestDlg::changeMech( int index )
{
    QString strMech = mMechCombo->currentText();
    long uMech = JS_PKCS11_GetCKMType( strMech.toStdString().c_str() );
    mMechText->setText( QString("0x%1").arg( uMech, 8, 16, QLatin1Char('0')).toUpper());
}

void DigestDlg::changeParam( const QString text )
{
    QString strLen = getDataLenString( DATA_HEX, mParamText->text() );
    mParamLenText->setText( QString("%1").arg( strLen ));
}

void DigestDlg::setSelectedSlot(int index)
{
    slotChanged(index);
}


void DigestDlg::initialize()
{
    mInitAutoCheck->setChecked(true);
    mInputTab->setCurrentIndex(0);
    status_type_ = STATUS_NONE;

    clearStatusLabel();

    if( manApplet->isLicense() == false ) mInputTab->setTabEnabled( 1, false );

    changeMech(0);
}

void DigestDlg::clearStatusLabel()
{
    mInitLabel->clear();
    mUpdateLabel->clear();
    mFinalLabel->clear();
}

void DigestDlg::setStatusInit( int rv )
{
    clearStatusLabel();

    if( rv == CKR_OK )
        mInitLabel->setText( "Init OK" );
    else
        mInitLabel->setText( QString( "Init Fail:%1" ).arg( rv ) );
}

void DigestDlg::setStatusUpdate( int rv, int count )
{
    if( rv == CKR_OK )
        mUpdateLabel->setText( QString( "|Update X %1" ).arg( count ) );
    else
        mUpdateLabel->setText( QString( "|Update Fail:%1").arg( rv ));
}

void DigestDlg::setStatusFinal( int rv )
{
    if( rv == CKR_OK )
        mFinalLabel->setText( QString( "|Final OK" ) );
    else
        mFinalLabel->setText( QString( "|Final Fail:%1").arg( rv ));
}

void DigestDlg::setStatusDigest( int rv )
{
    if( rv == CKR_OK )
        mFinalLabel->setText( QString( "|Digest OK" ) );
    else
        mFinalLabel->setText( QString( "|Digest Fail:%1").arg( rv ));
}

void DigestDlg::clickSelectKey()
{
    if( status_type_ == STATUS_INIT || status_type_ == STATUS_UPDATE )
    {
        manApplet->warnLog( tr( "Cannot be run in Init or Update state" ), this );
        return;
    }

    HsmManDlg hsmMan;
    hsmMan.setSelectedSlot( slot_index_ );
    hsmMan.setTitle( "Select Key" );

    hsmMan.setMode( HsmModeSelectSecretKey, HsmUsageAny );

    if( hsmMan.exec() == QDialog::Accepted )
    {
        mKeyLabelText->clear();
        mKeyObjectText->clear();

        QString strData = hsmMan.getData();
        QStringList listData = strData.split(":");
        if( listData.size() < 3 ) return;

        QString strType = listData.at(0);
        long hObj = listData.at(1).toLong();
        QString strID = listData.at(2);
        QString strLabel = manApplet->cryptokiAPI()->getLabel( session_, hObj );
        mKeyLabelText->setText( strLabel );
        mKeyObjectText->setText( QString("%1").arg( hObj ));
    }
}

void DigestDlg::clickDigestKey()
{
    int rv;
    CK_OBJECT_HANDLE hKey = -1;

    if( mKeyObjectText->text().isEmpty() )
    {
        clickSelectKey();
        if( mKeyObjectText->text().isEmpty() )
        {
            manApplet->warningBox( tr( "Select your key"), this );
            return;
        }
    }

    hKey = mKeyObjectText->text().toULong();

    rv = manApplet->cryptokiAPI()->DigestKey( session_, hKey );

    if( rv == CKR_OK )
    {
        QString strMsg = mStatusLabel->text();
        strMsg += "|DigestKey";

        mStatusLabel->setText( strMsg );
    }
    else
    {
        manApplet->warningBox( tr("DigestKey execution failure [%1]").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        mOutputText->setText("");
    }
}

int DigestDlg::clickInit()
{
    int rv = -1;
    update_cnt_ = 0;

    BIN binParam = {0,0};
    CK_MECHANISM stMech;

    memset( &stMech, 0x00, sizeof(stMech) );

    QString strMech = mMechCombo->currentText();
    stMech.mechanism = JS_PKCS11_GetCKMType( strMech.toStdString().c_str());

    QString strParam = mParamText->text();
    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam);
        stMech.pParameter = binParam.pVal;
        stMech.ulParameterLen = binParam.nLen;
    }

    clearStatusLabel();

    rv = manApplet->cryptokiAPI()->DigestInit( session_, &stMech );

    if( rv == CKR_OK )
    {
        mOutputText->setText( "" );
        status_type_ = STATUS_INIT;
    }
    else
    {
        manApplet->warningBox( tr("DigestInit execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        mOutputText->setText("");
    }

    setStatusInit( rv );

    return rv;
}

void DigestDlg::clickUpdate()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;

    QString strInput = mInputText->toPlainText();
    if( strInput.isEmpty() )
    {
        manApplet->warningBox(tr("Enter input value."), this );
        mInputText->setFocus();

        return;
    }

    BIN binInput = {0,0};
    if( mInputCombo->currentIndex() == 0 )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    rv = manApplet->cryptokiAPI()->DigestUpdate( session_, binInput.pVal, binInput.nLen );

    if( rv == CKR_OK )
    {
        update_cnt_++;
        status_type_ = STATUS_UPDATE;
    }
    else
    {
        manApplet->warningBox( tr("DigestUpdate execution failure [%1]").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        mOutputText->setText("");
    }

    setStatusUpdate( rv, update_cnt_ );
}

void DigestDlg::clickFinal()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;

    unsigned char sDigest[512];
    CK_ULONG uDigestLen = 512;
    BIN binDigest = {0,0};

    memset( sDigest, 0x00, sizeof(sDigest) );

    rv = manApplet->cryptokiAPI()->DigestFinal( session_, sDigest, &uDigestLen );

    if( rv == CKR_OK )
    {
        JS_BIN_set( &binDigest, sDigest, uDigestLen );
        mOutputText->setText( getHexString( binDigest.pVal, binDigest.nLen) );
        status_type_ = STATUS_FINAL;
    }
    else
    {
        manApplet->warningBox( tr("DigestFinal execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        status_type_ = STATUS_NONE;
    }

    setStatusFinal( rv );
    JS_BIN_reset( &binDigest );
}

void DigestDlg::clickDigest()
{
    int index = mInputTab->currentIndex();

    if( index == 0 )
    {
        runDataDigest();
    }
    else
    {
        if( manApplet->isLicense() == false )
        {
            QString strMsg = tr( "This feature requires a license." );
            manApplet->warningBox( strMsg, this );
            return;
        }

        if( mRunThreadCheck->isChecked() )
            runFileDigestThread();
        else
            runFileDigest();
    }
}

void DigestDlg::runDataDigest()
{
    int rv = -1;

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("Enter input value"), this );
        mInputText->setFocus();
        return;
    }

    if( mInitAutoCheck->isChecked() )
    {
        rv = clickInit();
        if( rv != CKR_OK ) return;
    }

    BIN binInput = {0,0};

    getBINFromString( &binInput, mInputCombo->currentText(), strInput );

    unsigned char sDigest[512];
    CK_ULONG uDigestLen = 64;
    BIN binDigest = {0,0};

    memset( sDigest, 0x00, sizeof(sDigest) );

    rv = manApplet->cryptokiAPI()->Digest( session_, binInput.pVal, binInput.nLen, sDigest, &uDigestLen );

    if( rv == CKR_OK )
    {
        char *pHex = NULL;
        JS_BIN_set( &binDigest, sDigest, uDigestLen );
        JS_BIN_encodeHex( &binDigest, &pHex );
        mOutputText->setText( pHex );
        status_type_ = STATUS_FINAL;
    }
    else
    {
        manApplet->warningBox( tr("Digest execution failure [%1]").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        mOutputText->setText("");
        status_type_ = STATUS_NONE;
    }

    setStatusDigest( rv );
}

void DigestDlg::runFileDigest()
{
    int ret = -1;
    int nRead = 0;
    int nPartSize = manApplet->settingsMgr()->fileReadSize();
    int nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;
    int nPercent = 0;

    QString strSrcFile = mSrcFileText->text();
    BIN binPart = {0,0};

    if( strSrcFile.length() < 1)
    {
        manApplet->warningBox( tr( "Find source file"), this );
        mSrcFileText->setFocus();
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mHashProgBar->setValue( 0 );
    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    nLeft = fileSize;

    if( mInitAutoCheck->isChecked() )
    {
        ret = clickInit();
        if( ret != CKR_OK )
        {
            manApplet->warningBox( tr("failed to initialize digest [%1]").arg(ret), this );
            return;
        }
    }

    FILE *fp = fopen( strSrcFile.toLocal8Bit().toStdString().c_str(), "rb" );

    if( fp == NULL )
    {
        manApplet->elog( QString( "failed to read file [%1]").arg( strSrcFile ));
        goto end;
    }

    manApplet->log( QString( "TotalSize: %1 BlockSize: %2").arg( fileSize).arg( nPartSize ));


    while( nLeft > 0 )
    {
        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 )
        {
            manApplet->warnLog( tr( "fail to read file: %1").arg( nRead ), this );
            goto end;
        }

        ret = manApplet->cryptokiAPI()->DigestUpdate( session_, binPart.pVal, binPart.nLen );
        if( ret != CKR_OK )
        {
            manApplet->warningBox( tr("DigestUpdate execution failure [%1]").arg( JS_PKCS11_GetErrorMsg(ret)), this );
            goto end;
        }

        status_type_ = STATUS_UPDATE;
        update_cnt_++;
        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mHashProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        update();
    }

    fclose( fp );
    manApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mHashProgBar->setValue( 100 );

        if( ret == CKR_OK )
        {
            setStatusUpdate( ret, update_cnt_ );
            clickFinal();
        }
    }

end :
    JS_BIN_reset( &binPart );
}

void DigestDlg::clickClose()
{
    this->hide();
}

void DigestDlg::inputChanged()
{
    QString strInput = mInputText->toPlainText();
    QString strLen = getDataLenString( mInputCombo->currentText(), strInput );
    mInputLenText->setText( QString("%1").arg( strLen ));
}

void DigestDlg::outputChanged()
{
    QString strOutput = mOutputText->text();
    QString strLen = getDataLenString( DATA_HEX, strOutput );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void DigestDlg::clickInputClear()
{
    mInputText->clear();
}

void DigestDlg::clickOutputClear()
{
    mOutputText->clear();
}

void DigestDlg::clickFindSrcFile()
{
    QString strPath = mSrcFileText->text();
    strPath = manApplet->curFilePath( strPath );

    QString strSrcFile = findFile( this, JS_FILE_TYPE_ALL, strPath );

    if( strSrcFile.length() > 0 )
    {
        QFileInfo fileInfo;
        fileInfo.setFile( strSrcFile );

        qint64 fileSize = fileInfo.size();
        QDateTime cTime = fileInfo.lastModified();

        QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));

        mSrcFileText->setText( strSrcFile );
        mSrcFileSizeText->setText( QString("%1").arg( fileSize ));
        mSrcFileInfoText->setText( strInfo );
        mHashProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
    }
}

void DigestDlg::runFileDigestThread()
{
    int ret = 0;

    if( mInitAutoCheck->isChecked() )
    {
        ret = clickInit();
        if( ret != CKR_OK )
        {
            manApplet->warningBox( tr("failed to initialize digest [%1]").arg(ret), this );
            return;
        }
    }

    startTask();
}

void DigestDlg::startTask()
{
    if( thread_ != nullptr ) delete thread_;

    thread_ = new DigestThread;

    CK_SESSION_HANDLE hSession = getSessionHandle();

    QString strSrcFile = mSrcFileText->text();

    if( strSrcFile.length() < 1)
    {
        manApplet->warningBox( tr( "Find source file"), this );
        mSrcFileText->setFocus();
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    connect(thread_, &DigestThread::taskFinished, this, &DigestDlg::onTaskFinished);
    connect( thread_, &DigestThread::taskUpdate, this, &DigestDlg::onTaskUpdate);

    thread_->setSession( hSession );
    thread_->setSrcFile( strSrcFile );
    thread_->start();
}

void DigestDlg::onTaskFinished()
{
    manApplet->log("Task finished");

    clickFinal();

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void DigestDlg::onTaskUpdate( int nUpdate )
{
    manApplet->log( QString("Update: %1").arg( nUpdate ));
    int nFileSize = mFileTotalSizeText->text().toInt();
    int nPercent = (nUpdate * 100) / nFileSize;
    update_cnt_++;
    status_type_ = STATUS_UPDATE;
    setStatusUpdate( CKR_OK, update_cnt_ );

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mHashProgBar->setValue( nPercent );
}
