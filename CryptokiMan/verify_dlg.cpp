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

#include "verify_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"
#include "settings_mgr.h"
#include "mech_mgr.h"
#include "verify_thread.h"
#include "hsm_man_dlg.h"
#include "object_view_dlg.h"

static QStringList sMechSignSymList;
static QStringList sMechSignAsymList;

static QStringList sKeyList = { "PUBLIC", "SECRET" };


VerifyDlg::VerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;

    update_cnt_ = 0;
    thread_ = NULL;

    setupUi(this);
    setAcceptDrops( true );

    initUI();

    mInputText->setFocus();
    mVerifyBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mDataTab->layout()->setSpacing(5);
    mDataTab->layout()->setMargin(5);
    mFileTab->layout()->setSpacing(5);
    mFileTab->layout()->setMargin(5);

    mInputClearBtn->setFixedWidth(34);
    mSignClearBtn->setFixedWidth(34);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

VerifyDlg::~VerifyDlg()
{
    if( thread_ ) delete thread_;

    if( status_type_ == STATUS_INIT || status_type_ == STATUS_UPDATE )
        resetFinal();
}

void VerifyDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void VerifyDlg::dropEvent(QDropEvent *event)
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

void VerifyDlg::initUI()
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
    mSignText->setPlaceholderText( tr( "Hex value" ) );

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));
    connect( mParamText, SIGNAL(textChanged(const QString)), this, SLOT(changeParam(const QString)));
    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));

    connect( mResetBtn, SIGNAL(clicked(bool)), this, SLOT(clickReset()));
    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));

    connect( mSelectBtn, SIGNAL(clicked()), this, SLOT(clickSelect()));
    connect( mObjectViewBtn, SIGNAL(clicked()), this, SLOT(clickObjectView()));

    connect( mVerifyRecoverInitBtn, SIGNAL(clicked()), this, SLOT(clickVerifyRecoverInit()));
    connect( mVerifyRecoverBtn, SIGNAL(clicked()), this, SLOT(clickVerifyRecover()));

    connect( mInputTypeCombo, SIGNAL( currentIndexChanged(int)), this, SLOT(changeInput()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(changeInput()));
    connect( mSignText, SIGNAL(textChanged()), this, SLOT(changeSign()));

    connect( mInputClearBtn, SIGNAL( clicked() ), this, SLOT(clickInputClear()));
    connect( mSignClearBtn, SIGNAL(clicked()), this, SLOT(clickSignClear()));
    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));


    initialize();
    keyTypeChanged(0);
    mVerifyBtn->setDefault(true);

    mLabelText->setPlaceholderText( tr( "Select a key from HSM Man" ));
    mParamText->setPlaceholderText( tr( "Hex value" ));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

void VerifyDlg::setSlotIndex(int index)
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

void VerifyDlg::changeType( int type )
{
    if( type == OBJ_SECRET_IDX )
        mKeyTypeCombo->setCurrentIndex(1);
    else
        mKeyTypeCombo->setCurrentIndex(0);
}

void VerifyDlg::setObject( int type, long hObj )
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

void VerifyDlg::initialize()
{
    mInitAutoCheck->setChecked(true);
    mInputTab->setCurrentIndex(0);
    status_type_ = STATUS_NONE;

    clearStatusLabel();

    if( manApplet->isLicense() == false ) mInputTab->setTabEnabled( 1, false );
}

void VerifyDlg::setSrcFileInfo( const QString strFile )
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
        mVerifyProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
    }
}

void VerifyDlg::clearStatusLabel()
{
    mStatusLabel->setText( "Status" );
    mInitText->clear();
    mUpdateText->clear();
    mFinalText->clear();
}

void VerifyDlg::setStatusInit( int rv )
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

void VerifyDlg::setStatusUpdate( int rv, int count )
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

void VerifyDlg::setStatusFinal( int rv )
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

void VerifyDlg::setStatusVerify( int rv )
{
    if( rv == CKR_OK )
    {
        mStatusLabel->setText( QString( "Verify OK" ) );
    }
    else
    {
        mStatusLabel->setText( QString( "%1").arg( P11ERR(rv) ));
    }
}

void VerifyDlg::keyTypeChanged( int index )
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

void VerifyDlg::changeParam(const QString text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mParamLenText->setText( QString("%1").arg( strLen ));
}

void VerifyDlg::mechChanged( int index )
{
    QString strMech = mMechCombo->currentText();

    if( strMech.length() < 1 )
        mMechText->clear();
    else
    {
        long uMech = JS_PKCS11_GetCKMType( strMech.toStdString().c_str() );
        mMechText->setText(QString( getMechHex(uMech)));
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

void VerifyDlg::changeInput()
{    
    QString strType = mInputTypeCombo->currentText();
    QString strLen = getDataLenString( strType, mInputText->toPlainText() );

    mInputLenText->setText( QString("%1").arg( strLen ));
}

void VerifyDlg::changeSign()
{
    QString strLen = getDataLenString( DATA_HEX, mSignText->toPlainText() );

    mSignLenText->setText( QString("%1").arg( strLen ));
}

void VerifyDlg::clickReset()
{
    clearStatusLabel();

    mFileReadSizeText->clear();
    mFileTotalSizeText->clear();
    mVerifyProgBar->setValue(0);

    if( status_type_ == STATUS_INIT || status_type_ == STATUS_UPDATE )
        resetFinal();
}

int VerifyDlg::clickInit()
{
    int rv = -1;
    update_cnt_ = 0;

    CK_MECHANISM sMech;
    BIN binParam = {0,0};
    CK_RSA_PKCS_PSS_PARAMS sRSA_PSS;

    memset( &sMech, 0x00, sizeof(sMech));
    memset( &sRSA_PSS, 0x00, sizeof(sRSA_PSS));

    if( mObjectText->text().isEmpty() )
    {
        clickSelect();
        if( mObjectText->text().isEmpty() )
        {
            manApplet->warningBox( tr( "Select your key"), this );
            return -1;
        }
    }

    long uObject = mObjectText->text().toLong();

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

    rv = manApplet->cryptokiAPI()->VerifyInit( slot_info_.getSessionHandle(), &sMech, uObject );
    setStatusInit( rv );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("VerifyInit execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    status_type_ = STATUS_INIT;
    return rv;
}

void VerifyDlg::clickUpdate()
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

    rv = manApplet->cryptokiAPI()->VerifyUpdate( slot_info_.getSessionHandle(), binInput.pVal, binInput.nLen );

    if( rv != CKR_OK )
    {
        setStatusUpdate( rv, update_cnt_ );
        manApplet->warningBox( tr("VerifyUpdate execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    update_cnt_++;
    setStatusUpdate( rv, update_cnt_ );
    status_type_ = STATUS_UPDATE;
}

void VerifyDlg::clickFinal()
{
    int rv = -1;

    QString strSign = mSignText->toPlainText();
    if( strSign.isEmpty() )
    {
        manApplet->warningBox( tr( "Enter signature"), this );
        mSignText->setFocus();
        return;
    }

    BIN binSign = {0,0};
    rv = getBINFromString( &binSign, DATA_HEX, strSign );
    if( rv < 0 )
    {
        manApplet->formatWarn( rv, this );
        return;
    }

    rv = manApplet->cryptokiAPI()->VerifyFinal( slot_info_.getSessionHandle(), binSign.pVal, binSign.nLen );
    setStatusFinal( rv );

    if( rv != CKR_OK )
    {
        status_type_ = STATUS_NONE;
        manApplet->warningBox( tr("Signature value is incorrect [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
    }
    else
    {
        status_type_ = STATUS_FINAL;
        manApplet->messageBox( tr("Signature value is correct"), this );
    }

    JS_BIN_reset( &binSign );
}

void VerifyDlg::resetFinal()
{
    int rv = -1;

    QString strSign = mSignText->toPlainText();

    BIN binSign = {0,0};
    getBINFromString( &binSign, DATA_HEX, strSign );

    rv = manApplet->cryptokiAPI()->VerifyFinal( slot_info_.getSessionHandle(), binSign.pVal, binSign.nLen );

    if( rv != CKR_OK )
    {
        status_type_ = STATUS_NONE;
    }
    else
    {
        status_type_ = STATUS_FINAL;
    }

    JS_BIN_reset( &binSign );
}

void VerifyDlg::clickVerify()
{
    int index = mInputTab->currentIndex();

    if( index == 0 )
        runDataVerify();
    else
    {
        if( manApplet->isLicense() == false )
        {
            QString strMsg = tr( "This feature requires a license." );
            manApplet->warningBox( strMsg, this );
            return;
        }

        if( mRunThreadCheck->isChecked() )
            runFileVerifyThread();
        else
            runFileVerify();
    }
}

void VerifyDlg::runDataVerify()
{
    int rv = -1;

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("Please enter your data."), this );
        mInputText->setFocus();
        return;
    }

    QString strSign = mSignText->toPlainText();
    if( strSign.isEmpty() )
    {
        manApplet->warningBox(tr( "Please enter signature." ), this );
        mSignText->setFocus();
        return;
    }

    if( mInitAutoCheck->isChecked() )
    {
        rv = clickInit();
        if( rv != CKR_OK ) return;
    }
    else
    {
        if( status_type_ != STATUS_INIT )
        {
            manApplet->warningBox( tr( "Init execution is required" ), this );
            return;
        }
    }

    BIN binInput = {0,0};
    QString strType = mInputTypeCombo->currentText();
    rv = getBINFromString( &binInput, strType, strInput );
    if( rv < 0 )
    {
        manApplet->formatWarn( rv, this );
        return;
    }

    BIN binSign = {0,0};
    rv = getBINFromString( &binSign, DATA_HEX, strSign );
    if( rv < 0 )
    {
        JS_BIN_reset( &binInput );
        manApplet->formatWarn( rv, this );
        return;
    }

    rv = manApplet->cryptokiAPI()->Verify( slot_info_.getSessionHandle(), binInput.pVal, binInput.nLen, binSign.pVal, binSign.nLen );
    setStatusVerify( rv );

    if( rv != CKR_OK )
    {
        status_type_ = STATUS_NONE;
        manApplet->warningBox( tr( "Signature value is incorrect [%1]" ).arg(JS_PKCS11_GetErrorMsg(rv)), this );
    }
    else
    {
        status_type_ = STATUS_FINAL;
        manApplet->messageBox( tr( "Signature value is correct" ), this );
    }
}

void VerifyDlg::runFileVerify()
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

    mVerifyProgBar->setValue( 0 );
    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    nLeft = fileSize;

    QString strSign = mSignText->toPlainText();
    if( strSign.isEmpty() )
    {
        manApplet->warningBox(tr( "Please enter signature." ), this );
        return;
    }

    if( mInitAutoCheck->isChecked() )
    {
        ret = clickInit();
        if( ret != CKR_OK )
        {
            manApplet->warningBox( tr("failed to initialize verify:%1").arg(ret), this );
            return;
        }
    }
    else
    {
        if( status_type_ != STATUS_INIT )
        {
            manApplet->warningBox( tr( "Init execution is required" ), this );
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

        ret = manApplet->cryptokiAPI()->VerifyUpdate( slot_info_.getSessionHandle(), binPart.pVal, binPart.nLen );
        if( ret != CKR_OK )
        {
            setStatusUpdate( ret, update_cnt_ );
            manApplet->warningBox( tr("VerifyUpdate execution failure [%1]").arg( JS_PKCS11_GetErrorMsg(ret)), this );
            goto end;
        }

        update_cnt_++;
        setStatusUpdate( ret, update_cnt_ );
        status_type_ = STATUS_UPDATE;
        nReadSize += nRead;
        nPercent = int( ( nReadSize * 100 ) / fileSize );

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mVerifyProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        update();
    }

    fclose( fp );
    manApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mVerifyProgBar->setValue( 100 );

        if( ret == CKR_OK )
        {   
            clickFinal();
        }
    }

end :
    JS_BIN_reset( &binPart );
}

void VerifyDlg::clickClose()
{
    this->hide();
}

void VerifyDlg::clickSelect()
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
        hsmMan.setMode( HsmModeSelectSecretKey, HsmUsageVerify );
    else
        hsmMan.setMode( HsmModeSelectPublicKey, HsmUsageVerify );

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

void VerifyDlg::clickObjectView()
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

void VerifyDlg::clickVerifyRecoverInit()
{
    int rv = -1;

    CK_MECHANISM sMech;
    BIN binParam = {0,0};
    long uObject = mObjectText->text().toLong();

    sMech.mechanism = JS_PKCS11_GetCKMType( mMechCombo->currentText().toStdString().c_str());
    QString strParam = mParamText->text();

    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );
        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }

    rv = manApplet->cryptokiAPI()->VerifyRecoverInit( slot_info_.getSessionHandle(), &sMech, uObject );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("VerifyRecoverInit execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }
}

void VerifyDlg::clickVerifyRecover()
{
    int rv = -1;

    unsigned char sData[1024];
    long ulDataLen = 0;

    QString strSign = mSignText->toPlainText();
    if( strSign.isEmpty() )
    {
        manApplet->warningBox(tr( "Please enter signature." ), this );
        return;
    }

    BIN binSign = {0,0};
    JS_BIN_decodeHex( strSign.toStdString().c_str(), &binSign );

    rv = manApplet->cryptokiAPI()->VerifyRecover( slot_info_.getSessionHandle(), binSign.pVal, binSign.nLen, sData, (CK_ULONG_PTR)&ulDataLen );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "Signature value is incorrect [%1]" ).arg(JS_PKCS11_GetErrorMsg(rv)), this );
    }
    else
    {
        mInputTypeCombo->setCurrentText( kDataHex );
        mInputText->setPlainText( getHexString( sData, ulDataLen ));
        manApplet->messageBox( tr( "Signature value is correct" ), this );
    }
}

void VerifyDlg::clickInputClear()
{
    mInputText->clear();
}

void VerifyDlg::clickSignClear()
{
    mSignText->clear();
}

void VerifyDlg::clickFindSrcFile()
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
        mVerifyProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
    }
}

void VerifyDlg::runFileVerifyThread()
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
    else
    {
        if( status_type_ != STATUS_INIT )
        {
            manApplet->warningBox( tr( "Init execution is required" ), this );
            return;
        }
    }

    startTask();
}

void VerifyDlg::startTask()
{
    if( thread_ != nullptr ) delete thread_;

    thread_ = new VerifyThread;

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

    connect(thread_, &VerifyThread::taskFinished, this, &VerifyDlg::onTaskFinished);
    connect( thread_, &VerifyThread::taskUpdate, this, &VerifyDlg::onTaskUpdate);

    thread_->setSession( slot_info_.getSessionHandle() );
    thread_->setSrcFile( strSrcFile );
    thread_->start();
}

void VerifyDlg::onTaskFinished()
{
    manApplet->log("Task finished");

    clickFinal();

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void VerifyDlg::onTaskUpdate( qint64 nUpdate )
{
    manApplet->log( QString("Update: %1").arg( nUpdate ));
    qint64 nFileSize = mFileTotalSizeText->text().toLongLong();
    int nPercent = int( (nUpdate * 100) / nFileSize );
    update_cnt_++;
    setStatusUpdate( CKR_OK, update_cnt_ );
    status_type_ = STATUS_UPDATE;

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mVerifyProgBar->setValue( nPercent );
}
