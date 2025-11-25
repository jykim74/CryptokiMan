/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileInfo>
#include <QDateTime>

#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

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
#include "object_view_dlg.h"

static QStringList sMechSignAsymList;
static QStringList sMechSignSymList;

static QStringList sKeyList = { "PRIVATE", "SECRET" };

SignDlg::SignDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    update_cnt_ = 0;
    thread_ = NULL;

    setupUi(this);
    setAcceptDrops( true );

    initUI();

    mSignBtn->setDefault( true );
    mInputText->setFocus();

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

    if( status_type_ == STATUS_INIT || status_type_ == STATUS_UPDATE )
        clickFinal();
}

void SignDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void SignDlg::dropEvent(QDropEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();

        for (const QUrl &url : urls)
        {
            manApplet->log( QString( "url: %1").arg( url.toLocalFile() ));
            mInputTab->setCurrentIndex(1);
            setSrcFileInfo( url.toLocalFile() );
            break;
        }
    } else if (event->mimeData()->hasText()) {

    }
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

    mInputTypeCombo->addItems( kDataTypeList );
    mKeyTypeCombo->addItems(sKeyList);
    mMechCombo->addItems( sMechSignAsymList );
    mPSSHashAlgCombo->addItems( kMechSHAList );
    mPSSMgfCombo->addItems( kMGFList );

    mRunThreadCheck->setChecked(true);

    setLineEditHexOnly( mParamText, tr("Hex value" ));
    mOutputText->setPlaceholderText( tr( "Hex value" ));

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));
    connect( mParamText, SIGNAL(textChanged(const QString)), this, SLOT(changeParam(const QString)));
    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));

    connect( mResetBtn, SIGNAL(clicked(bool)), this, SLOT(clickReset()));
    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mSignBtn, SIGNAL(clicked()), this, SLOT(clickSign()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));
    connect( mSelectBtn, SIGNAL(clicked()), this, SLOT(clickSelect()));
    connect( mObjectViewBtn, SIGNAL(clicked()), this, SLOT(clickObjectView()));

    connect( mSignRecoverInitBtn, SIGNAL(clicked()), this, SLOT(clickSignRecoverInit()));
    connect( mSignRecoverBtn, SIGNAL(clicked()), this, SLOT(clickSignRecover()));

    connect( mInputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeInput()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(changeInput()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(changeOutput()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));
    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));

    initialize();
    keyTypeChanged(0);

    mLabelText->setPlaceholderText( tr( "Select a key from HSM Man" ));
    mParamText->setPlaceholderText( tr( "Hex value" ));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

void SignDlg::setSlotIndex(int index)
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

    keyTypeChanged( 0 );
}

void SignDlg::changeType( int type )
{
    if( type == OBJ_SECRET_IDX )
    {
        mKeyTypeCombo->setCurrentIndex(1);

    }
    else
    {
        mKeyTypeCombo->setCurrentIndex(0);

    }
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

    manApplet->cryptokiAPI()->GetAttributeValue2( slot_info_.getSessionHandle(), hObj, CKA_LABEL, &binVal );
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
    status_type_ = STATUS_NONE;

    clearStatusLabel();

    if( manApplet->isLicense() == false ) mInputTab->setTabEnabled( 1, false );
}

void SignDlg::setSrcFileInfo( const QString strFile )
{
    if( strFile.length() > 0 )
    {
        QFileInfo fileInfo;
        fileInfo.setFile( strFile );

        qint64 fileSize = fileInfo.size();
        QDateTime cTime = fileInfo.lastModified();

        QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));

        mSrcFileText->setText( strFile );
        mSrcFileSizeText->setText( QString("%1").arg( fileSize ));
        mSrcFileInfoText->setText( strInfo );
        mSignProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
    }
}

void SignDlg::clearStatusLabel()
{
    mStatusLabel->setText( "Status" );
    mInitText->clear();
    mUpdateText->clear();
    mFinalText->clear();
}

void SignDlg::setStatusInit( int rv )
{
    clearStatusLabel();

    if( rv == CKR_OK )
    {
        mStatusLabel->setText( "Init OK" );
        mInitText->setText( "OK" );
    }
    else
    {
        mStatusLabel->setText( QString( "%1" ).arg( P11ERR(rv) ) );
        mInitText->setText( QString("%1").arg(rv));
    }
}

void SignDlg::setStatusUpdate( int rv, int count )
{
    if( rv == CKR_OK )
    {
        mStatusLabel->setText( "Update OK" );
        mUpdateText->setText( QString("%1").arg(count));
    }
    else
    {
        mStatusLabel->setText( QString( "%1" ).arg( P11ERR(rv) ) );
        mUpdateText->setText( QString("%1").arg(rv));
    }
}

void SignDlg::setStatusFinal( int rv )
{
    if( rv == CKR_OK )
    {
        mStatusLabel->setText( "Final OK" );
        mFinalText->setText( QString( "OK" ) );
    }
    else
    {
        mStatusLabel->setText( QString( "%1" ).arg( P11ERR(rv) ) );
        mFinalText->setText( QString("%1").arg(rv));
    }
}

void SignDlg::setStatusSign( int rv )
{
    if( rv == CKR_OK )
    {
        mStatusLabel->setText( QString( "Sign OK" ) );
    }
    else
    {
        mStatusLabel->setText( QString( "%1").arg( P11ERR(rv) ));
    }
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
        mMechText->setText(QString( getMechHex(uMech )));
    }

    if( isRSA_PSS( JS_PKCS11_GetCKMType( strMech.toStdString().c_str() )) == true )
    {
        mPSSGroup->show();
        mParamGroup->hide();
    }
    else
    {
        mPSSGroup->hide();
        mParamGroup->show();
    }
}

void SignDlg::changeInput()
{   
    QString strType = mInputTypeCombo->currentText();
    QString strLen = getDataLenString( strType, mInputText->toPlainText() );

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

void SignDlg::clickReset()
{
    clearStatusLabel();

    if( status_type_ == STATUS_INIT || status_type_ == STATUS_UPDATE )
        clickFinal();
}

int SignDlg::clickInit()
{
    int rv = -1;
    update_cnt_ = 0;

    CK_MECHANISM sMech;
    BIN binParam = {0,0};
    CK_RSA_PKCS_PSS_PARAMS sRSA_PSS;

    memset( &sMech, 0x00, sizeof(sMech));
    memset( &sRSA_PSS, 0x00, sizeof(sRSA_PSS));

    sMech.mechanism = JS_PKCS11_GetCKMType( mMechCombo->currentText().toStdString().c_str());

    if( isRSA_PSS( sMech.mechanism ) == true )
    {
        QString strHashAlg = mPSSHashAlgCombo->currentText();
        QString strMgf1 = mPSSMgfCombo->currentText();
        int nLen = mPSSLenText->text().toInt();

        sRSA_PSS.hashAlg = JS_PKCS11_GetCKMType( strHashAlg.toStdString().c_str() );
        sRSA_PSS.mgf = JS_PKCS11_GetCKGType( strMgf1.toStdString().c_str() );
        sRSA_PSS.sLen = nLen;

        sMech.pParameter = &sRSA_PSS;
        sMech.ulParameterLen = sizeof(sRSA_PSS);
    }
    else
    {
        QString strParam = mParamText->text();
        if( !strParam.isEmpty() )
        {
            JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );

            sMech.pParameter = binParam.pVal;
            sMech.ulParameterLen = binParam.nLen;
        }
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
    rv = manApplet->cryptokiAPI()->SignInit( slot_info_.getSessionHandle(), &sMech, uObject );

    setStatusInit( rv );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText( "" );
        manApplet->warningBox( tr("fail to run SignInit(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
    }
    else
    {
        status_type_ = STATUS_INIT;
        mOutputText->setPlainText( "" );
    }

    return rv;
}

void SignDlg::clickUpdate()
{
    int rv = -1;

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox(tr( "Please enter your data."), this );
        return;
    }

    BIN binInput = {0,0};
    QString strType = mInputTypeCombo->currentText();

    rv = getBINFromString( &binInput, strType, strInput );
    if( rv < 0 )
    {
        manApplet->formatWarn( rv, this );
        return;
    }

    rv = manApplet->cryptokiAPI()->SignUpdate( slot_info_.getSessionHandle(), binInput.pVal, binInput.nLen );
    if( rv != CKR_OK )
    {
        setStatusUpdate( rv, update_cnt_ );
        manApplet->warningBox(tr("SignUpdate execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    status_type_ = STATUS_UPDATE;
    update_cnt_++;
    setStatusUpdate( rv, update_cnt_ );
}

void SignDlg::clickFinal()
{
    int rv = -1;

    unsigned char sSign[1024];
    long uSignLen = 1024;

    rv = manApplet->cryptokiAPI()->SignFinal( slot_info_.getSessionHandle(), sSign, (CK_ULONG_PTR)&uSignLen );

    setStatusFinal( rv );

    if( rv != CKR_OK )
    {
        status_type_ = STATUS_NONE;
        manApplet->warningBox( tr("SignFinal execution failure [%1]").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    status_type_ = STATUS_FINAL;
    BIN binSign = {0,0};
    JS_BIN_set( &binSign, sSign, uSignLen );
    mOutputText->setPlainText( getHexString( binSign.pVal, binSign.nLen) );

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
    QString strType = mInputTypeCombo->currentText();

    rv = getBINFromString( &binInput, strType, strInput );
    if( rv < 0 )
    {
        manApplet->formatWarn( rv, this );
        return;
    }

    unsigned char sSign[1024];
    long uSignLen = 1024;

    rv = manApplet->cryptokiAPI()->Sign( slot_info_.getSessionHandle(), binInput.pVal, binInput.nLen, sSign, (CK_ULONG_PTR)&uSignLen );
    setStatusSign( rv );

    if( rv != CKR_OK )
    {
        status_type_ = STATUS_NONE;
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("Sign execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    char *pHex = NULL;
    BIN binSign = {0,0};
    JS_BIN_set( &binSign, sSign, uSignLen);
    JS_BIN_encodeHex( &binSign, &pHex );
    mOutputText->setPlainText( pHex );

    status_type_ = STATUS_FINAL;

    if( pHex ) JS_free(pHex);
    JS_BIN_reset(&binSign);
}

void SignDlg::runFileSign()
{
    int ret = -1;

    int nRead = 0;
    int nPartSize = manApplet->settingsMgr()->fileReadSize();
    qint64 nReadSize = 0;
    int nLeft = 0;
    qint64 nOffset = 0;
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

        ret = manApplet->cryptokiAPI()->SignUpdate( slot_info_.getSessionHandle(), binPart.pVal, binPart.nLen );
        if( ret != CKR_OK )
        {
            setStatusUpdate( ret, update_cnt_ );
            manApplet->warningBox( tr("SignUpdate execution failure [%1]").arg( JS_PKCS11_GetErrorMsg(ret)), this );
            goto end;
        }

        update_cnt_++;
        setStatusUpdate( ret, update_cnt_ );
        status_type_ = STATUS_UPDATE;
        nReadSize += nRead;
        nPercent = int( ( nReadSize * 100 ) / fileSize );

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
    if( status_type_ == STATUS_INIT || status_type_ == STATUS_UPDATE )
    {
        manApplet->warnLog( tr( "Cannot be run in Init or Update state" ), this );
        return;
    }

    HsmManDlg hsmMan;
    hsmMan.setSlotIndex( slot_index_ );
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
        QString strLabel = manApplet->cryptokiAPI()->getLabel( slot_info_.getSessionHandle(), hObj );
        mLabelText->setText( strLabel );
        mObjectText->setText( QString("%1").arg( hObj ));
    }
}

void SignDlg::clickObjectView()
{
    if( status_type_ == STATUS_INIT || status_type_ == STATUS_UPDATE )
    {
        manApplet->warnLog( tr( "Cannot be run in Init or Update state" ), this );
        return;
    }

    QString strObject = mObjectText->text();
    if( strObject.length() < 1 )
    {
        manApplet->warningBox( tr( "There is no object" ), this );
        return;
    }

    ObjectViewDlg objectView;
    objectView.setSlotIndex( slot_index_ );
    objectView.setObject( strObject.toLong() );
    objectView.exec();
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
    rv = manApplet->cryptokiAPI()->SignRecoverInit( slot_info_.getSessionHandle(), &sMech, uObject );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText( "" );
        manApplet->warningBox( tr("SignRecoverInit execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
    }
    else
    {
        mOutputText->setPlainText( "" );
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
    QString strType = mInputTypeCombo->currentText();

    rv = getBINFromString( &binInput, strType, strInput );
    if( rv < 0 )
    {
        manApplet->formatWarn( rv, this );
        return;
    }

    unsigned char sSign[1024];
    long uSignLen = 1024;

    rv = manApplet->cryptokiAPI()->SignRecover( slot_info_.getSessionHandle(), binInput.pVal, binInput.nLen, sSign, (CK_ULONG_PTR)&uSignLen );

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

    QString strSrcFile = manApplet->findFile( this, JS_FILE_TYPE_ALL, strPath );

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

    thread_->setSession( slot_info_.getSessionHandle() );
    thread_->setSrcFile( strSrcFile );
    thread_->start();
}

void SignDlg::onTaskFinished()
{
    manApplet->log("Task finished");

    clickFinal();

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void SignDlg::onTaskUpdate( qint64 nUpdate )
{
    manApplet->log( QString("Update: %1").arg( nUpdate ));
    qint64 nFileSize = mFileTotalSizeText->text().toLongLong();
    int nPercent = int( (nUpdate * 100) / nFileSize );
    update_cnt_++;
    setStatusUpdate( CKR_OK, update_cnt_ );
    status_type_ = STATUS_UPDATE;

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mSignProgBar->setValue( nPercent );
}
