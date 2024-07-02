/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileInfo>
#include <QDateTime>

#include "verify_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"
#include "settings_mgr.h"
#include "mech_mgr.h"
#include "verify_thread.h"

static QStringList sMechSignSymList;
static QStringList sMechSignAsymList;

static QStringList sKeyList = { "PUBLIC", "SECRET" };


VerifyDlg::VerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    session_ = -1;
    update_cnt_ = 0;
    thread_ = NULL;

    setupUi(this);

    initUI();
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

VerifyDlg::~VerifyDlg()
{
    if( thread_ ) delete thread_;
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
        sMechSignAsymList = kMechSignAsymNoLicenseList;
    }

    mKeyTypeCombo->addItems(sKeyList);
    mMechCombo->addItems( sMechSignAsymList );

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));
    connect( mParamText, SIGNAL(textChanged(const QString)), this, SLOT(changeParam(const QString)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));

    connect( mVerifyRecoverInitBtn, SIGNAL(clicked()), this, SLOT(clickVerifyRecoverInit()));
    connect( mVerifyRecoverBtn, SIGNAL(clicked()), this, SLOT(clickVerifyRecover()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(changeInput()));
    connect( mSignText, SIGNAL(textChanged()), this, SLOT(changeSign()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mSignClearBtn, SIGNAL(clicked()), this, SLOT(clickSignClear()));
    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));
    connect( mVerifyThreadBtn, SIGNAL(clicked()), this, SLOT(runFileVerifyThread()));


    initialize();
    keyTypeChanged(0);
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

void VerifyDlg::slotChanged(int index)
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

void VerifyDlg::setSelectedSlot(int index)
{
    slotChanged( index );

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

    manApplet->cryptokiAPI()->GetAttributeValue2( session_, hObj, CKA_LABEL, &binVal );
    JS_BIN_string( &binVal, &pLabel );
    JS_BIN_reset( &binVal );

    mLabelCombo->setCurrentText( pLabel );
    mObjectText->setText( QString("%1").arg( hObj ));

    if( pLabel ) JS_free( pLabel );
}

void VerifyDlg::initialize()
{
    mInitAutoCheck->setChecked(true);
    mInputTab->setCurrentIndex(0);

    if( manApplet->isLicense() == false ) mInputTab->setTabEnabled( 1, false );
}

void VerifyDlg::appendStatusLabel( const QString& strLabel )
{
    QString strStatus = mStatusLabel->text();
    strStatus += strLabel;
    mStatusLabel->setText( strStatus );
}

void VerifyDlg::keyTypeChanged( int index )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[10];
    CK_ULONG uCnt = 0;

    CK_ULONG uMaxObjCnt = manApplet->settingsMgr()->findMaxObjectsCount();
    CK_OBJECT_HANDLE sObjects[uMaxObjCnt];
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;

    mMechCombo->clear();

    if( mKeyTypeCombo->currentText() == sKeyList[0] )
    {
        objClass = CKO_PUBLIC_KEY;
        mMechCombo->addItems( sMechSignAsymList );
    }
    else if( mKeyTypeCombo->currentText() == sKeyList[1] )
    {
        objClass = CKO_SECRET_KEY;
        mMechCombo->addItems( sMechSignSymList );
    }

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_VERIFY;
    sTemplate[uCnt].pValue = &kTrue;
    sTemplate[uCnt].ulValueLen = sizeof(CK_BBOOL);
    uCnt++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( session_ );
    if( rv != CKR_OK ) return;

    mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char    *pStr = NULL;
        BIN binLabel = {0,0};

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );

        QVariant objVal = QVariant((int)sObjects[i]);
        JS_BIN_string( &binLabel, &pStr );
        mLabelCombo->addItem( pStr, objVal );
        if( pStr ) JS_free( pStr );
        JS_BIN_reset(&binLabel);
    }

    if( uObjCnt > 0 )
    {
        QString strHandle = QString("%1").arg( sObjects[0] );
        mObjectText->setText( strHandle );
    }
}

void VerifyDlg::labelChanged( int index )
{
    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}

void VerifyDlg::changeParam(const QString text )
{
    int nLen = getDataLen( DATA_HEX, text );
    mParamLenText->setText( QString("%1").arg( nLen ));
}

void VerifyDlg::changeInput()
{
    int nType = DATA_STRING;

    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mInputText->toPlainText() );

    mInputLenText->setText( QString("%1").arg( nLen ));
}

void VerifyDlg::changeSign()
{
    int nLen = getDataLen( DATA_HEX, mSignText->toPlainText() );

    mSignLenText->setText( QString("%1").arg( nLen ));
}

int VerifyDlg::clickInit()
{
    int rv = -1;
    update_cnt_ = 0;

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

    rv = manApplet->cryptokiAPI()->VerifyInit( session_, &sMech, uObject );

    if( rv != CKR_OK )
    {
        mStatusLabel->setText("");
        manApplet->warningBox( tr("VerifyInit execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    mStatusLabel->setText( "Init" );
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

    if( mInputStringRadio->isChecked() )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputHexRadio->isChecked() )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputBase64Radio->isChecked() )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    rv = manApplet->cryptokiAPI()->VerifyUpdate( session_, binInput.pVal, binInput.nLen );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("VerifyUpdate execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    appendStatusLabel( "|Update" );
}

void VerifyDlg::clickFinal()
{
    int rv = -1;

    QString strSign = mSignText->toPlainText();

    if( strSign.isEmpty() )
    {
        manApplet->warningBox( tr( "Enter signature."), this );
        return;
    }

    BIN binSign = {0,0};
    JS_BIN_decodeHex( strSign.toStdString().c_str(), &binSign );

    rv = manApplet->cryptokiAPI()->VerifyFinal( session_, binSign.pVal, binSign.nLen );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("Signature value is incorrect [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
    }
    else
    {
        manApplet->messageBox( tr("Signature value is correct"), this );
    }

    appendStatusLabel( "|Final" );
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
        return;
    }

    QString strSign = mSignText->toPlainText();
    if( strSign.isEmpty() )
    {
        manApplet->warningBox(tr( "Please enter signature." ), this );
        return;
    }

    if( mInitAutoCheck->isChecked() )
    {
        rv = clickInit();
        if( rv != CKR_OK ) return;
    }

    BIN binInput = {0,0};

    if( mInputStringRadio->isChecked() )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputHexRadio->isChecked() )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputBase64Radio->isChecked() )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    BIN binSign = {0,0};
    JS_BIN_decodeHex( strSign.toStdString().c_str(), &binSign );

    rv = manApplet->cryptokiAPI()->Verify( session_, binInput.pVal, binInput.nLen, binSign.pVal, binSign.nLen );

    if( rv != CKR_OK )
        manApplet->warningBox( tr( "Signature value is incorrect [%1]" ).arg(JS_PKCS11_GetErrorMsg(rv)), this );
    else
        manApplet->messageBox( tr( "Signature value is correct" ), this );

    QString strRes = mStatusLabel->text();
    strRes += "|Verify";

    mStatusLabel->setText(strRes);
}

void VerifyDlg::runFileVerify()
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
        if( nRead <= 0 ) break;

        ret = manApplet->cryptokiAPI()->VerifyUpdate( session_, binPart.pVal, binPart.nLen );
        if( ret != CKR_OK )
        {
            manApplet->warningBox( tr("VerifyUpdate execution failure [%1]").arg( JS_PKCS11_GetErrorMsg(ret)), this );
            goto end;
        }

        update_cnt_++;
        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mVerifyProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        repaint();
    }

    fclose( fp );
    manApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mVerifyProgBar->setValue( 100 );

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

void VerifyDlg::clickClose()
{
    this->hide();
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

    rv = manApplet->cryptokiAPI()->VerifyRecoverInit( session_, &sMech, uObject );

    if( rv != CKR_OK )
    {
        mStatusLabel->setText("");
        manApplet->warningBox( tr("VerifyRecoverInit execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    mStatusLabel->setText( "VerifyRecoverInit" );
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

    rv = manApplet->cryptokiAPI()->VerifyRecover( session_, binSign.pVal, binSign.nLen, sData, (CK_ULONG_PTR)&ulDataLen );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "Signature value is incorrect [%1]" ).arg(JS_PKCS11_GetErrorMsg(rv)), this );
    }
    else
    {
        mInputHexRadio->setChecked(true);
        mInputText->setPlainText( getHexString( sData, ulDataLen ));
        manApplet->messageBox( tr( "Signature value is correct" ), this );
    }

    QString strRes = mStatusLabel->text();
    strRes += "|VerifyRecover";

    mStatusLabel->setText(strRes);
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
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    connect(thread_, &VerifyThread::taskFinished, this, &VerifyDlg::onTaskFinished);
    connect( thread_, &VerifyThread::taskUpdate, this, &VerifyDlg::onTaskUpdate);

    thread_->setSession( session_ );
    thread_->setSrcFile( strSrcFile );
    thread_->start();
}

void VerifyDlg::onTaskFinished()
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

void VerifyDlg::onTaskUpdate( int nUpdate )
{
    manApplet->log( QString("Update: %1").arg( nUpdate ));
    int nFileSize = mFileTotalSizeText->text().toInt();
    int nPercent = (nUpdate * 100) / nFileSize;
    update_cnt_++;

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mVerifyProgBar->setValue( nPercent );
}
