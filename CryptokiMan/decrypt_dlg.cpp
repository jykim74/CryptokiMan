/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileInfo>
#include <QDateTime>
#include <QFileDialog>

#include "decrypt_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"
#include "settings_mgr.h"
#include "mech_mgr.h"
#include "decrypt_thread.h"


static QStringList sKeyList = { "SECRET", "PRIVATE" };
static QStringList sMechEncSymList;
static QStringList sMechEncAsymList;

DecryptDlg::DecryptDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    session_ = -1;
    update_cnt_ = 0;
    thread_ = NULL;

    setupUi(this);
    initUI();
#if defined(Q_OS_MAC)
    layout()->setSpacing(3);
#endif
}

DecryptDlg::~DecryptDlg()
{
    if( thread_ ) delete thread_;
}

void DecryptDlg::initUI()
{
    if( manApplet->isLicense() == true )
    {
        if( manApplet->settingsMgr()->useDeviceMech() )
        {
            sMechEncSymList = manApplet->mechMgr()->getDecList( MECH_TYPE_SYM );
            sMechEncAsymList = manApplet->mechMgr()->getDecList( MECH_TYPE_ASYM );
        }
        else
        {
            sMechEncSymList = kMechEncSymList;
            sMechEncAsymList = kMechEncAsymList;
        }
    }
    else
    {
        sMechEncSymList = kMechEncSymNoLicenseList;
        sMechEncAsymList = kMechEncAsymList;
    }

    mKeyTypeCombo->addItems(sKeyList);
    mMechCombo->addItems( sMechEncSymList );
    mOutputCombo->addItems( kDataTypeList );
    mAADTypeCombo->addItems( kDataTypeList );

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mDecryptBtn, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mParamText, SIGNAL(textChanged(const QString&)), this, SLOT(paramChanged()));
    connect( mAADText, SIGNAL(textChanged(const QString&)), this, SLOT(aadChanged()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));
    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));
    connect( mFindDstFileBtn, SIGNAL(clicked()), this, SLOT(clickFindDstFile()));
    connect( mDecThreadBtn, SIGNAL(clicked()), this, SLOT(runFileDecryptThread()));

    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));


    initialize();
    keyTypeChanged(0);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

void DecryptDlg::setMechanism( void *pMech )
{
    if( pMech == NULL ) return;
    CK_MECHANISM_PTR pPtr = (CK_MECHANISM *)pMech;
    long nMech = JS_PKCS11_GetCKMType( mMechCombo->currentText().toStdString().c_str());

    pPtr->mechanism = nMech;

    if( nMech == CKM_AES_GCM || nMech == CKM_AES_CCM )
    {
        BIN binIV = {0,0};
        BIN binAAD = {0,0};
        int nReqLen = mReqTagLenText->text().toInt();
        QString strIV = mParamText->text();
        QString strAAD = mAADText->text();

        JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
        getBINFromString( &binAAD, mAADTypeCombo->currentText(), strAAD );

        CK_GCM_PARAMS_PTR gcmParam;
        gcmParam = (CK_GCM_PARAMS *)JS_calloc( 1, sizeof(CK_GCM_PARAMS));

        gcmParam->ulIvLen = binIV.nLen;
        gcmParam->pIv = binIV.pVal;
        gcmParam->ulAADLen = binAAD.nLen;
        gcmParam->pAAD = binAAD.pVal;
        gcmParam->ulIvBits = binIV.nLen * 8;
        gcmParam->ulTagBits = nReqLen * 8;

        pPtr->pParameter = gcmParam;
        pPtr->ulParameterLen = sizeof(CK_GCM_PARAMS);
    }
    else
    {
        BIN binParam = {0,0};
        QString strParam = mParamText->text();
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );

        pPtr->pParameter = binParam.pVal;
        pPtr->ulParameterLen = binParam.nLen;
    }
}

void DecryptDlg::freeMechanism( void *pMech )
{
    CK_MECHANISM_PTR pPtr = (CK_MECHANISM_PTR)pMech;

    if( pPtr->mechanism == CKM_AES_GCM || pPtr->mechanism == CKM_AES_CBC )
    {
        CK_GCM_PARAMS_PTR gcmParam = (CK_GCM_PARAMS_PTR)pPtr->pParameter;

        if( gcmParam->pIv ) JS_free( gcmParam->pIv );
        if( gcmParam->pAAD ) JS_free( gcmParam->pAAD );
    }
    else
    {
        if( pPtr->pParameter ) JS_free( pPtr->pParameter );
    }
}

void DecryptDlg::slotChanged(int index)
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

void DecryptDlg::mechChanged( int index )
{
    QString strMech = mMechCombo->currentText();
    QStringList algList = strMech.split( "_" );

    int size = algList.size();

    QString strLast = algList.at(size-1);

    if( strLast == "GCM" || strLast == "CCM" )
    {
        mAEGroup->setEnabled(true);
    }
    else
    {
        mAEGroup->setEnabled(false);
    }
}

void DecryptDlg::setSelectedSlot(int index)
{
    slotChanged(index);

    keyTypeChanged( 0 );
}

void DecryptDlg::setObject( int type, long hObj )
{
    BIN binVal = {0,0};
    char *pLabel = NULL;

    if( type == OBJ_SECRET_IDX )
    {
        mKeyTypeCombo->setCurrentText( sKeyList[0] );
    }
    else if( type == OBJ_PRIKEY_IDX )
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

void DecryptDlg::changeType( int type )
{
    if( type == OBJ_SECRET_IDX )
        mKeyTypeCombo->setCurrentIndex(0);
    else
        mKeyTypeCombo->setCurrentIndex(1);
}

void DecryptDlg::initialize()
{
    mInitAutoCheck->setChecked(true);
    mInputTab->setCurrentIndex(0);

    if( manApplet->isLicense() == false ) mInputTab->setTabEnabled( 1, false );
}

void DecryptDlg::appendStatusLabel( const QString& strLabel )
{
    QString strStatus = mStatusLabel->text();
    strStatus += strLabel;
    mStatusLabel->setText( strStatus );
}

void DecryptDlg::keyTypeChanged( int index )
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
        objClass = CKO_SECRET_KEY;
        mMechCombo->addItems(sMechEncSymList);
    }
    else if( mKeyTypeCombo->currentText() == sKeyList[1] )
    {
        objClass = CKO_PRIVATE_KEY;
        mMechCombo->addItems(sMechEncAsymList);
    }

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_DECRYPT;
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

void DecryptDlg::labelChanged( int index )
{
    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}

void DecryptDlg::inputChanged()
{
    QString strInput = mInputText->toPlainText();
    int nLen = getDataLen( DATA_HEX, strInput );
    mInputLenText->setText( QString("%1").arg( nLen ));
}

void DecryptDlg::outputChanged()
{
    QString strOutput = mOutputText->toPlainText();
    int nLen = getDataLen( mOutputCombo->currentText(), strOutput );
    mOutputLenText->setText( QString("%1").arg(nLen));
}

void DecryptDlg::paramChanged()
{
    QString strParam = mParamText->text();
    int nLen = getDataLen( DATA_HEX, strParam );
    mParamLenText->setText( QString("%1").arg(nLen));
}

void DecryptDlg::aadChanged()
{
    QString strAAD = mAADText->text();
    int nLen = getDataLen( mAADTypeCombo->currentText(), strAAD );
    mAADLenText->setText( QString("%1").arg(nLen));
}

void DecryptDlg::clickInputClear()
{
    mInputText->clear();
}

void DecryptDlg::clickOutputClear()
{
    mOutputText->clear();
}

void DecryptDlg::clickFindSrcFile()
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
        mDecProgBar->setValue(0);

        QStringList nameExt = strSrcFile.split(".");
        QString strDstName = QString( "%1.dst" ).arg( nameExt.at(0) );
        if( strSrcFile == strDstName )
        {
            strDstName += "_dst";
        }

        mDstFileText->setText( strDstName );

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
        mDstFileInfoText->clear();
        mDstFileSizeText->clear();
    }
}

void DecryptDlg::clickFindDstFile()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strFilter;
    QString strPath = mDstFileText->text();

    QString selectedFilter;
    QString fileName = QFileDialog::getSaveFileName( this,
                                                     tr("Decrypt Files"),
                                                     strPath,
                                                     strFilter,
                                                     &selectedFilter,
                                                     options );

    if( fileName.length() > 0 ) mDstFileText->setText( fileName );
}

int DecryptDlg::clickInit()
{
    int rv = -1;
    update_cnt_ = 0;

    long hObject = mObjectText->text().toLong();

    CK_MECHANISM sMech;

    memset( &sMech, 0x00, sizeof(sMech));

#if 0
    BIN binParam = {0,0};
    sMech.mechanism = JS_PKCS11_GetCKMType( mMechCombo->currentText().toStdString().c_str());

    QString strParam = mParamText->text();

    if( !strParam.isEmpty() )
    {
        JS_BIN_decodeHex( strParam.toStdString().c_str(), &binParam );
        sMech.pParameter = binParam.pVal;
        sMech.ulParameterLen = binParam.nLen;
    }
#else
    setMechanism( &sMech );
#endif

    rv = manApplet->cryptokiAPI()->DecryptInit( session_, &sMech, hObject );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText("");
        mStatusLabel->setText("");
        manApplet->warningBox( tr("DecryptInit execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    mOutputText->setPlainText("");
    mStatusLabel->setText( "Init" );

    freeMechanism( &sMech );

    return rv;
}

void DecryptDlg::clickUpdate()
{
    int rv = -1;

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("Enter your data."), this );
        mInputText->setFocus();
        return;
    }

    BIN binInput = {0,0};

    getBINFromString( &binInput, DATA_HEX, strInput );

    unsigned char *pDecPart = NULL;
    long uDecPartLen = binInput.nLen;

    pDecPart = (unsigned char *)JS_malloc( binInput.nLen );
    if( pDecPart == NULL ) return;

    BIN binDecPart = {0,0};

    rv = manApplet->cryptokiAPI()->DecryptUpdate( session_, binInput.pVal, binInput.nLen, pDecPart, (CK_ULONG_PTR)&uDecPartLen );

    if( rv != CKR_OK )
    {
        if( pDecPart ) JS_free( pDecPart );
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("DecryptUpdate execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        return;
    }

    JS_BIN_set( &binDecPart, pDecPart, uDecPartLen );

    QString strDec = getStringFromBIN( &binDecPart, mOutputCombo->currentText() );
    mOutputText->appendPlainText( strDec );
    JS_BIN_reset( &binDecPart );

    appendStatusLabel( "|Update" );
    if( pDecPart ) JS_free( pDecPart );
}

void DecryptDlg::clickFinal()
{
    int rv = -1;

    unsigned char *pDecPart = NULL;
    long uDecPartLen = mInputText->toPlainText().length();

    BIN binDecPart = {0,0};

    rv = manApplet->cryptokiAPI()->DecryptFinal( session_, NULL, (CK_ULONG_PTR)&uDecPartLen );

    if( rv != CKR_OK )
    {
        if( pDecPart ) JS_free( pDecPart );
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("DecryptFinal execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    if( uDecPartLen > 0 )
    {
        pDecPart = (unsigned char *)JS_malloc( uDecPartLen );
        if( pDecPart == NULL )return;
    }

    rv = manApplet->cryptokiAPI()->DecryptFinal( session_, pDecPart, (CK_ULONG_PTR)&uDecPartLen );

    if( rv != CKR_OK )
    {
        if( pDecPart ) JS_free( pDecPart );
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("DecryptFinal execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    appendStatusLabel( "|Final" );

    JS_BIN_set( &binDecPart, pDecPart, uDecPartLen );

    if( mInputTab->currentIndex() == 0 )
    {
        QString strDec = getStringFromBIN( &binDecPart, mOutputCombo->currentText() );
        mOutputText->appendPlainText( strDec );
    }
    else
    {
        QString strDstPath = mDstFileText->text();
        JS_BIN_fileAppend( &binDecPart, strDstPath.toLocal8Bit().toStdString().c_str() );
    }

    JS_BIN_reset( &binDecPart );
    if( pDecPart ) JS_free( pDecPart );
    JS_BIN_reset( &binDecPart );
}

void DecryptDlg::clickDecrypt()
{
    int index = mInputTab->currentIndex();

    if( index == 0 )
        runDataDecrypt();
    else
    {
        if( manApplet->isLicense() == false )
        {
            QString strMsg = tr( "This feature requires a license." );
            manApplet->warningBox( strMsg, this );
            return;
        }

        runFileDecrypt();
    }
}

void DecryptDlg::runDataDecrypt()
{
    int rv = -1;

    QString strInput = mInputText->toPlainText();
    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("Enter your data"), this );
        mInputText->setFocus();
        return;
    }

    if( mInitAutoCheck->isChecked() )
    {
        rv = clickInit();
        if( rv != CKR_OK ) return;
    }

    BIN binInput = {0,0};

    getBINFromString( &binInput, DATA_HEX, strInput );

    unsigned char *pDecData = NULL;
    long uDecDataLen = mInputText->toPlainText().length();
    pDecData = (unsigned char *)JS_malloc( mInputText->toPlainText().length() );

    rv = manApplet->cryptokiAPI()->Decrypt( session_, binInput.pVal, binInput.nLen, pDecData, (CK_ULONG_PTR)&uDecDataLen );

    if( rv != CKR_OK )
    {
        if( pDecData ) JS_free( pDecData );
        mOutputText->setPlainText( "" );
        manApplet->warningBox( tr("Decrypt execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    QString strRes = mStatusLabel->text();
    strRes += "|Decrypt";
    mStatusLabel->setText( strRes );

    BIN binDecData = {0,0};
    JS_BIN_set( &binDecData, pDecData, uDecDataLen );
    QString strDec = getStringFromBIN( &binDecData, mOutputCombo->currentText() );

    mOutputText->setPlainText( strDec );
    if( pDecData ) JS_free( pDecData );
    JS_BIN_reset( &binDecData );
}

void DecryptDlg::runFileDecrypt()
{
    int rv = -1;

    int nRead = 0;
    int nPartSize = manApplet->settingsMgr()->fileReadSize();
    int nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;
    int nPercent = 0;

    QString strSrcFile = mSrcFileText->text();
    BIN binPart = {0,0};
    BIN binDst = {0,0};

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mDecProgBar->setValue( 0 );
    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    nLeft = fileSize;
    QString strDstFile = mDstFileText->text();

    if( QFile::exists( strDstFile ) )
    {
        QString strMsg = tr( "The destination file(%1) already exists.\nDo you want to delete the file and continue?" ).arg( strDstFile );
        bool bVal = manApplet->yesOrNoBox( strMsg, this, false );

        if( bVal == true )
        {
            QFile::remove( strDstFile );
        }
        else
            return;
    }

    if( mInitAutoCheck->isChecked() )
        clickInit();

    FILE *fp = fopen( strSrcFile.toLocal8Bit().toStdString().c_str(), "rb" );
    if( fp == NULL )
    {
        manApplet->elog( QString( "failed to open file (%1)").arg( strSrcFile ));
        goto end;
    }

    manApplet->log( QString( "TotalSize: %1 BlockSize: %2").arg( fileSize).arg( nPartSize ));


    while( nLeft > 0 )
    {
        unsigned char *pDecPart = NULL;
        long uDecPartLen = 0;

        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 ) break;

        uDecPartLen = binPart.nLen + 64;

        pDecPart = (unsigned char *)JS_malloc( binPart.nLen + 64 );
        if( pDecPart == NULL ) return;

        rv = manApplet->cryptokiAPI()->DecryptUpdate( session_, binPart.pVal, binPart.nLen, pDecPart, (CK_ULONG_PTR)&uDecPartLen );

        if( rv != CKR_OK )
        {
            if( pDecPart ) JS_free( pDecPart );
            manApplet->warningBox( tr("DecryptUpdate execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
            goto end;
        }

        update_cnt_++;

        if( uDecPartLen > 0 )
        {
            JS_BIN_set( &binDst, pDecPart, uDecPartLen );
            JS_free( pDecPart );
            pDecPart = NULL;
            uDecPartLen = 0;
        }

        if( binDst.nLen > 0 )
            JS_BIN_fileAppend( &binDst, strDstFile.toLocal8Bit().toStdString().c_str() );

        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mDecProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        JS_BIN_reset( &binDst );
        repaint();
    }

    fclose( fp );
    manApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mDecProgBar->setValue( 100 );

        if( rv == 0 )
        {
            QString strMsg = QString( "|Update X %1").arg( update_cnt_ );
            appendStatusLabel( strMsg );
            clickFinal();

            QFileInfo fileInfo;
            fileInfo.setFile( strDstFile );
            qint64 fileSize = fileInfo.size();
            QDateTime cTime = fileInfo.lastModified();

            QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));
            mDstFileSizeText->setText( QString("%1").arg( fileSize ));
            mDstFileInfoText->setText( strInfo );
        }
    }

end :
    JS_BIN_reset( &binPart );
    JS_BIN_reset( &binDst );
}

void DecryptDlg::clickClose()
{
    this->hide();
}

void DecryptDlg::runFileDecryptThread()
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

void DecryptDlg::startTask()
{
    if( thread_ != nullptr ) delete thread_;

    thread_ = new DecryptThread;

    QString strSrcFile = mSrcFileText->text();

    if( strSrcFile.length() < 1)
    {
        manApplet->warningBox( tr( "Find source file"), this );
        return;
    }

    QString strDstFile = mDstFileText->text();

    if( QFile::exists( strDstFile ) )
    {
        QString strMsg = tr( "The target file[%1] is already exist.\nDo you want to delete the file and continue?" ).arg( strDstFile );
        bool bVal = manApplet->yesOrNoBox( strMsg, this, false );

        if( bVal == true )
        {
            QFile::remove( strDstFile );
        }
        else
            return;
    }


    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    connect(thread_, &DecryptThread::taskFinished, this, &DecryptDlg::onTaskFinished);
    connect( thread_, &DecryptThread::taskUpdate, this, &DecryptDlg::onTaskUpdate);

    thread_->setSession( session_ );
    thread_->setSrcFile( strSrcFile );
    thread_->setDstFile( strDstFile );
    thread_->start();
}

void DecryptDlg::onTaskFinished()
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

void DecryptDlg::onTaskUpdate( int nUpdate )
{
    manApplet->log( QString("Update: %1").arg( nUpdate ));
    int nFileSize = mFileTotalSizeText->text().toInt();
    int nPercent = (nUpdate * 100) / nFileSize;
    update_cnt_++;

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mDecProgBar->setValue( nPercent );
}
