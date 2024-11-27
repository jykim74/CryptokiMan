/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileInfo>
#include <QDateTime>

#include "sign_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"
#include "settings_mgr.h"
#include "mech_mgr.h"
#include "sign_thread.h"
#include "hsm_man_dlg.h"

static QStringList sMechSignAsymList;
static QStringList sMechSignSymList;

static QStringList sKeyList = { "PRIVATE", "SECRET" };

SignDlg::SignDlg(QWidget *parent) :
    QDialog(parent)
{
    session_ = -1;
    slot_index_ = -1;
    update_cnt_ = 0;
    thread_ = NULL;

    setupUi(this);
    initUI();

    mSignBtn->setDefault( true );

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

SignDlg::~SignDlg()
{
    if( thread_ ) delete thread_;
}

void SignDlg::initUI()
{
    if( manApplet->isLicense() )
    {
        if( manApplet->settingsMgr()->useDeviceMech() )
        {
            sMechSignSymList = manApplet->mechMgr()->getSignList( MECH_TYPE_SYM );
            sMechSignAsymList = manApplet->mechMgr()->getSignList( MECH_TYPE_ASYM );
        }
        else
        {
            sMechSignSymList = kMechSignSymList;
            sMechSignAsymList = kMechSignAsymList;
        }
    }
    else
    {
        sMechSignSymList = kMechSignSymList;
        sMechSignAsymList = kMechSignAsymList;
    }

    mKeyTypeCombo->addItems(sKeyList);
    mMechCombo->addItems( sMechSignAsymList );

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));
    connect( mParamText, SIGNAL(textChanged(const QString)), this, SLOT(changeParam(const QString)));
    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mSignBtn, SIGNAL(clicked()), this, SLOT(clickSign()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));
    connect( mSelectBtn, SIGNAL(clicked()), this, SLOT(clickSelect()));

    connect( mSignRecoverInitBtn, SIGNAL(clicked()), this, SLOT(clickSignRecoverInit()));
    connect( mSignRecoverBtn, SIGNAL(clicked()), this, SLOT(clickSignRecover()));

    connect( mInputHexRadio, SIGNAL(clicked()), this, SLOT(changeInput()));
    connect( mInputStringRadio, SIGNAL(clicked()), this, SLOT(changeInput()));
    connect( mInputBase64Radio, SIGNAL(clicked()), this, SLOT(changeInput()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(changeInput()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(changeOutput()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));
    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));

    initialize();
    keyTypeChanged(0);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

void SignDlg::slotChanged(int index)
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

void SignDlg::setSelectedSlot(int index)
{
    slotChanged( index );

    keyTypeChanged( 0 );
}

void SignDlg::changeType( int type )
{
    if( type == OBJ_SECRET_IDX )
        mKeyTypeCombo->setCurrentIndex(1);
    else
        mKeyTypeCombo->setCurrentIndex(0);
}

void SignDlg::setObject( int type, long hObj )
{
    BIN binVal = {0,0};
    char *pLabel = NULL;

    if( type == OBJ_PRIKEY_IDX )
    {
        mKeyTypeCombo->setCurrentText( sKeyList[0] );
    }
    else if( type == OBJ_SECRET_IDX )
    {
        mKeyTypeCombo->setCurrentText( sKeyList[1] );
    }

    manApplet->cryptokiAPI()->GetAttributeValue2( session_, hObj, CKA_LABEL, &binVal );
    JS_BIN_string( &binVal, &pLabel );
    JS_BIN_reset( &binVal );

    mLabelText->setText( pLabel );
    mObjectText->setText( QString("%1").arg( hObj ));

    if( pLabel ) JS_free( pLabel );
}

void SignDlg::initialize()
{
    mInitAutoCheck->setChecked(true);
    mInputTab->setCurrentIndex(0);

    if( manApplet->isLicense() == false ) mInputTab->setTabEnabled( 1, false );
}

void SignDlg::appendStatusLabel( const QString& strLabel )
{
    QString strStatus = mStatusLabel->text();
    strStatus += strLabel;
    mStatusLabel->setText( strStatus );
}

void SignDlg::keyTypeChanged( int index )
{
    mMechCombo->clear();

    if( mKeyTypeCombo->currentText() == sKeyList[0] )
    {
        mMechCombo->addItems( sMechSignAsymList );
    }
    else if( mKeyTypeCombo->currentText() == sKeyList[1] )
    {
        mMechCombo->addItems( sMechSignSymList );
    }

    mLabelText->clear();
    mObjectText->clear();
}

void SignDlg::mechChanged( int index )
{
    QString strMech = mMechCombo->currentText();

    if( strMech.length() < 1 )
        mMechText->clear();
    else
    {
        long uMech = JS_PKCS11_GetCKMType( strMech.toStdString().c_str() );
        mMechText->setText(QString("%1").arg( uMech, 8, 16, QLatin1Char('0')));
    }
}

void SignDlg::changeInput()
{
    int nType = DATA_STRING;

    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    QString strLen = getDataLenString( nType, mInputText->toPlainText() );

    mInputLenText->setText( QString("%1").arg( strLen ));
}

void SignDlg::changeOutput()
{
    QString strLen = getDataLenString( DATA_HEX, mOutputText->toPlainText() );

    mOutputLenText->setText( QString("%1").arg( strLen ));
}

void SignDlg::changeParam( const QString text )
{
    QString strLen = getDataLenString( DATA_HEX, mParamText->text() );
    mParamLenText->setText( QString("%1").arg( strLen ));
}

int SignDlg::clickInit()
{
    int rv = -1;
    update_cnt_ = 0;

    CK_MECHANISM sMech;
    BIN binParam = {0,0};

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = JS_PKCS11_GetCKMType( mMechCombo->currentText().toStdString().c_str());

    QString strParam = mParamText->text();
    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );

        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }

    if( mObjectText->text().isEmpty() )
    {
        clickSelect();
        if( mObjectText->text().isEmpty() )
        {
            manApplet->warningBox( tr( "Select your key"), this );
            return -1;
        }
    }

    CK_OBJECT_HANDLE uObject = mObjectText->text().toLong();
    rv = manApplet->cryptokiAPI()->SignInit( session_, &sMech, uObject );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText( "" );
        mStatusLabel->setText( "" );
        manApplet->warningBox( tr("fail to run SignInit(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
    }
    else
    {
        mOutputText->setPlainText( "" );
        mStatusLabel->setText( "Init" );
    }

    return rv;
}

void SignDlg::clickUpdate()
{
    int rv = -1;
    int nDataType = DATA_HEX;

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox(tr( "Please enter your data."), this );
        return;
    }

    BIN binInput = {0,0};

    if( mInputStringRadio->isChecked() )
        nDataType = DATA_STRING;
    else if( mInputHexRadio->isChecked() )
        nDataType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nDataType = DATA_BASE64;

    getBINFromString( &binInput, nDataType, strInput );

    rv = manApplet->cryptokiAPI()->SignUpdate( session_, binInput.pVal, binInput.nLen );

    if( rv != CKR_OK )
    {
        manApplet->warningBox(tr("SignUpdate execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    appendStatusLabel( "|Update" );
}

void SignDlg::clickFinal()
{
    int rv = -1;

    unsigned char sSign[1024];
    long uSignLen = 1024;

    rv = manApplet->cryptokiAPI()->SignFinal( session_, sSign, (CK_ULONG_PTR)&uSignLen );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("SignFinal execution failure [%1]").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        appendStatusLabel( QString( "|Final failure [%1]").arg( rv ));
        return;
    }


    BIN binSign = {0,0};
    JS_BIN_set( &binSign, sSign, uSignLen );
    mOutputText->setPlainText( getHexString( binSign.pVal, binSign.nLen) );

    appendStatusLabel( "|Final OK" );
    JS_BIN_reset(&binSign);
}

void SignDlg::clickSign()
{
    int index = mInputTab->currentIndex();

    if( index == 0 )
        runDataSign();
    else
    {
        if( manApplet->isLicense() == false )
        {
            QString strMsg = tr( "This feature requires a license." );
            manApplet->warningBox( strMsg, this );
            return;
        }

        if( mRunThreadCheck->isChecked() )
            runFileSignThread();
        else
            runFileSign();
    }
}

void SignDlg::runDataSign()
{
    int rv = -1;

    int nDataType = -1;
    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("Please enter your data."), this );
        mInputText->setFocus();
        return;
    }

    if( mInitAutoCheck->isChecked() )
    {
        rv = clickInit();
        if( rv != CKR_OK ) return;
    }

    BIN binInput = {0,0};

    if( mInputStringRadio->isChecked() )
        nDataType = DATA_STRING;
    else if( mInputHexRadio->isChecked() )
        nDataType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nDataType = DATA_BASE64;

    getBINFromString( &binInput, nDataType, strInput );

    unsigned char sSign[1024];
    long uSignLen = 1024;

    rv = manApplet->cryptokiAPI()->Sign( session_, binInput.pVal, binInput.nLen, sSign, (CK_ULONG_PTR)&uSignLen );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("Sign execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    char *pHex = NULL;
    BIN binSign = {0,0};
    JS_BIN_set( &binSign, sSign, uSignLen);
    JS_BIN_encodeHex( &binSign, &pHex );
    mOutputText->setPlainText( pHex );

    QString strRes = mStatusLabel->text();
    strRes += "|Sign";
    mStatusLabel->setText( strRes );

    if( pHex ) JS_free(pHex);
    JS_BIN_reset(&binSign);
}

void SignDlg::runFileSign()
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

    mSignProgBar->setValue( 0 );
    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    nLeft = fileSize;

    if( mInitAutoCheck->isChecked() )
    {
        ret = clickInit();
        if( ret != CKR_OK )
        {
            manApplet->warningBox( tr("failed to initialize sign [%1]").arg(ret), this );
            return;
        }
    }

    FILE *fp = fopen( strSrcFile.toLocal8Bit().toStdString().c_str(), "rb" );
    if( fp == NULL )
    {
        manApplet->elog( QString( "failed to open file (%1)").arg( strSrcFile ));
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

        ret = manApplet->cryptokiAPI()->SignUpdate( session_, binPart.pVal, binPart.nLen );
        if( ret != CKR_OK )
        {
            manApplet->warningBox( tr("SignUpdate execution failure [%1]").arg( JS_PKCS11_GetErrorMsg(ret)), this );
            goto end;
        }

        update_cnt_++;
        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mSignProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        update();
    }

    fclose( fp );
    manApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mSignProgBar->setValue( 100 );

        if( ret == CKR_OK )
        {
            QString strMsg = QString( "|Update X %1").arg( update_cnt_ );
            appendStatusLabel( strMsg );

            clickFinal();
        }
    }

end :
    JS_BIN_reset( &binPart );
}

void SignDlg::clickClose()
{
    this->hide();
}

void SignDlg::clickSelect()
{
    HsmManDlg hsmMan;
    hsmMan.setSelectedSlot( slot_index_ );
    hsmMan.setTitle( "Select Key" );

    if( mKeyTypeCombo->currentText() == "SECRET" )
        hsmMan.setMode( HsmModeSelectSecretKey, HsmUsageSign );
    else
        hsmMan.setMode( HsmModeSelectPrivateKey, HsmUsageSign );

    if( hsmMan.exec() == QDialog::Accepted )
    {
        mLabelText->clear();
        mObjectText->clear();

        QString strData = hsmMan.getData();
        QStringList listData = strData.split(":");
        if( listData.size() < 3 ) return;

        QString strType = listData.at(0);
        long hObj = listData.at(1).toLong();
        QString strID = listData.at(2);
        QString strLabel = manApplet->cryptokiAPI()->getLabel( session_, hObj );
        mLabelText->setText( strLabel );
        mObjectText->setText( QString("%1").arg( hObj ));
    }
}

void SignDlg::clickSignRecoverInit()
{
    int rv = -1;

    CK_MECHANISM sMech;
    BIN binParam = {0,0};

    sMech.mechanism = JS_PKCS11_GetCKMType( mMechCombo->currentText().toStdString().c_str());

    QString strParam = mParamText->text();
    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );

        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }

    CK_OBJECT_HANDLE uObject = mObjectText->text().toLong();
    rv = manApplet->cryptokiAPI()->SignRecoverInit( session_, &sMech, uObject );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText( "" );
        mStatusLabel->setText( "" );
        manApplet->warningBox( tr("SignRecoverInit execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
    }
    else
    {
        mOutputText->setPlainText( "" );
        mStatusLabel->setText( "SignRecoverInit" );
    }
}

void SignDlg::clickSignRecover()
{
    int rv = -1;

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("Please enter your data."), this );
        return;
    }

    BIN binInput = {0,0};

    if( mInputStringRadio->isChecked() )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length());
    else if( mInputHexRadio->isChecked() )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputBase64Radio->isChecked() )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    unsigned char sSign[1024];
    long uSignLen = 1024;

    rv = manApplet->cryptokiAPI()->SignRecover( session_, binInput.pVal, binInput.nLen, sSign, (CK_ULONG_PTR)&uSignLen );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("SignRecover execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    char *pHex = NULL;
    BIN binSign = {0,0};
    JS_BIN_set( &binSign, sSign, uSignLen);
    JS_BIN_encodeHex( &binSign, &pHex );
    mOutputText->setPlainText( pHex );

    QString strRes = mStatusLabel->text();
    strRes += "|SignRecover";
    mStatusLabel->setText( strRes );

    if( pHex ) JS_free(pHex);
    JS_BIN_reset(&binSign);
}

void SignDlg::clickInputClear()
{
    mInputText->clear();
}

void SignDlg::clickOutputClear()
{
    mOutputText->clear();
}

void SignDlg::clickFindSrcFile()
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
        mSignProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
    }
}

void SignDlg::runFileSignThread()
{
    int ret = 0;

    if( mInitAutoCheck->isChecked() )
    {
        ret = clickInit();
        if( ret != CKR_OK )
        {
            manApplet->warningBox( tr("failed to initialize [%1]").arg(ret), this );
            return;
        }
    }

    startTask();
}

void SignDlg::startTask()
{
    if( thread_ != nullptr ) delete thread_;

    thread_ = new SignThread;

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

    connect(thread_, &SignThread::taskFinished, this, &SignDlg::onTaskFinished);
    connect( thread_, &SignThread::taskUpdate, this, &SignDlg::onTaskUpdate);

    thread_->setSession( session_ );
    thread_->setSrcFile( strSrcFile );
    thread_->start();
}

void SignDlg::onTaskFinished()
{
    manApplet->log("Task finished");


    QString strStatus = QString( "|Update X %1").arg( update_cnt_ );
    appendStatusLabel( strStatus );

    clickFinal();

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void SignDlg::onTaskUpdate( int nUpdate )
{
    manApplet->log( QString("Update: %1").arg( nUpdate ));
    int nFileSize = mFileTotalSizeText->text().toInt();
    int nPercent = (nUpdate * 100) / nFileSize;
    update_cnt_++;

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mSignProgBar->setValue( nPercent );
}
