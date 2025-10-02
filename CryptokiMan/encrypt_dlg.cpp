/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileInfo>
#include <QDateTime>
#include <QFileDialog>

#include "encrypt_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"
#include "settings_mgr.h"
#include "mech_mgr.h"
#include "encrypt_thread.h"
#include "hsm_man_dlg.h"
#include "object_view_dlg.h"

#include "js_error.h"

static QStringList sKeyList = { "SECRET", "PUBLIC" };

static QStringList sMechEncSymList;
static QStringList sMechEncAsymList;

EncryptDlg::EncryptDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    thread_ = nullptr;

    setupUi(this);
    initUI();

    mEncryptBtn->setDefault(true);
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

EncryptDlg::~EncryptDlg()
{
    if( thread_ ) delete thread_;

    if( status_type_ == STATUS_INIT || status_type_ == STATUS_UPDATE )
        clickFinal();
}

void EncryptDlg::initUI()
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
        sMechEncSymList = kMechEncSymList;
        sMechEncAsymList = kMechEncAsymList;
    }

    mKeyTypeCombo->addItems(sKeyList);
    mMechCombo->addItems( sMechEncSymList );
    mInputCombo->addItems( kDataTypeList );
    mAADTypeCombo->addItems( kDataTypeList );
    mOAEPHashAlgCombo->addItems( kMechSHAList );
    mOAEPMgfCombo->addItems( kMGFList );
    mOutputText->setPlaceholderText( tr( "Hex value" ) );

    mRunThreadCheck->setChecked(true);

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mEncryptBtn, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));
    connect( mSelectBtn, SIGNAL(clicked()), this, SLOT(clickSelect()));
    connect( mObjectViewBtn, SIGNAL(clicked()), this, SLOT(clickObjectView()));

    connect( mInputCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(inputChanged()));
    connect( mOAEPSourceText, SIGNAL(textChanged(QString)), this, SLOT(oaepSourceChanged()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mParamText, SIGNAL(textChanged(const QString&)), this, SLOT(paramChanged()));
    connect( mAADText, SIGNAL(textChanged(const QString&)), this, SLOT(aadChanged()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));
    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));
    connect( mFindDstFileBtn, SIGNAL(clicked()), this, SLOT(clickFindDstFile()));

    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));

    initialize();
    keyTypeChanged(0);

    mLabelText->setPlaceholderText( tr( "Select a key from HSM Man" ));
    mParamText->setPlaceholderText( tr( "Hex value" ));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

void EncryptDlg::setMechanism( void *pMech )
{
    if( pMech == NULL ) return;
    CK_MECHANISM_PTR pPtr = (CK_MECHANISM *)pMech;
    long nMech = JS_PKCS11_GetCKMType( mMechCombo->currentText().toStdString().c_str());

    pPtr->mechanism = nMech;

    if( nMech == CKM_AES_GCM )
    {
        BIN binIV = {0,0};
        BIN binAAD = {0,0};

        int nReqLen = mReqTagLenText->text().toInt();
        QString strIV = mParamText->text();
        QString strAAD = mAADText->text();

        JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
        getBINFromString( &binAAD, mAADTypeCombo->currentText(), strAAD );

        setAES_GCMParam( &binIV, &binAAD, nReqLen, pPtr );
    }
    else if( nMech == CKM_AES_CCM )
    {
        BIN binIV = {0,0};
        BIN binAAD = {0,0};

        int nReqLen = mReqTagLenText->text().toInt();
        int nSrcLen = mSrcLengthText->text().toInt();

        QString strIV = mParamText->text();
        QString strAAD = mAADText->text();

        JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
        getBINFromString( &binAAD, mAADTypeCombo->currentText(), strAAD );

        setAES_CCMParam( &binIV, &binAAD, nSrcLen, nReqLen, pPtr );
    }
    else if( nMech == CKM_RSA_PKCS_OAEP )
    {
        BIN binSrc = {0,0};
        CK_RSA_PKCS_OAEP_PARAMS *pOAEPParam = NULL;
        QString strHashAlg = mOAEPHashAlgCombo->currentText();
        QString strMgf = mOAEPMgfCombo->currentText();
        QString strSrc = mOAEPSourceText->text();

        pOAEPParam = (CK_RSA_PKCS_OAEP_PARAMS *)JS_calloc( 1, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
        getBINFromString( &binSrc, DATA_HEX, strSrc.toStdString().c_str() );

        pOAEPParam->hashAlg = JS_PKCS11_GetCKMType( strHashAlg.toStdString().c_str() );
        pOAEPParam->mgf = JS_PKCS11_GetCKGType( strMgf.toStdString().c_str() );
        pOAEPParam->source = CKZ_DATA_SPECIFIED;
        pOAEPParam->pSourceData = binSrc.pVal;
        pOAEPParam->ulSourceDataLen = binSrc.nLen;

        pPtr->pParameter = pOAEPParam;
        pPtr->ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
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

void EncryptDlg::freeMechanism( void *pMech )
{
    CK_MECHANISM_PTR pPtr = (CK_MECHANISM_PTR)pMech;

    if( pPtr->mechanism == CKM_AES_GCM )
    {
        CK_GCM_PARAMS_PTR gcmParam = (CK_GCM_PARAMS_PTR)pPtr->pParameter;

        if( gcmParam->pIv ) JS_free( gcmParam->pIv );
        if( gcmParam->pAAD ) JS_free( gcmParam->pAAD );
        JS_free( gcmParam );
    }
    else if( pPtr->mechanism == CKM_AES_CCM )
    {
        CK_CCM_PARAMS_PTR ccmParam = (CK_CCM_PARAMS_PTR)pPtr->pParameter;

        if( ccmParam->pNonce ) JS_free( ccmParam->pNonce );
        if( ccmParam->pAAD ) JS_free( ccmParam->pAAD );
        JS_free( ccmParam );
    }
    else if( pPtr->mechanism == CKM_RSA_PKCS_OAEP )
    {
        CK_RSA_PKCS_OAEP_PARAMS_PTR oaepParam = (CK_RSA_PKCS_OAEP_PARAMS_PTR)pPtr->pParameter;
        if( oaepParam->pSourceData ) JS_free( oaepParam->pSourceData );
        JS_free( oaepParam );
    }
    else
    {
        if( pPtr->pParameter ) JS_free( pPtr->pParameter );
    }
}

void EncryptDlg::mechChanged( int index )
{
    QString strMech = mMechCombo->currentText();
    QStringList algList = strMech.split( "_" );

    long uMech = JS_PKCS11_GetCKMType( strMech.toStdString().c_str() );
    mMechText->setText( QString( getMechHex(uMech )));

    int size = algList.size();

    QString strLast = algList.at(size-1);

    if( strLast == "GCM" || strLast == "CCM" )
    {
        mAEGroup->setEnabled(true);

        if( strLast == "CCM" )
        {
            mSrcLengthLabel->setEnabled( true );
            mSrcLengthText->setEnabled( true );
        }
        else
        {
            mSrcLengthLabel->setEnabled( false );
            mSrcLengthText->setEnabled( false );
        }
    }
    else
    {
        mAEGroup->setEnabled(false);
    }

    if( uMech == CKM_RSA_PKCS_OAEP )
    {
        mOAEPGroup->show();
        mParamGroup->hide();
    }
    else
    {
        mOAEPGroup->hide();
        mParamGroup->show();
    }
}

void EncryptDlg::setSlotIndex(int index)
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

void EncryptDlg::setObject( int type, long hObj )
{
    BIN binVal = {0,0};
    char *pLabel = NULL;

    if( type == OBJ_SECRET_IDX )
    {
        mKeyTypeCombo->setCurrentText( sKeyList[0] );
    }
    else if( type == OBJ_PUBKEY_IDX )
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

void EncryptDlg::changeType( int type )
{
    if( type == OBJ_SECRET_IDX )
        mKeyTypeCombo->setCurrentIndex(0);
    else
        mKeyTypeCombo->setCurrentIndex(1);
}

void EncryptDlg::initialize()
{
    mInitAutoCheck->setChecked(true);
    mInputTab->setCurrentIndex(0);
    status_type_ = STATUS_NONE;

    clearStatusLabel();

    if( manApplet->isLicense() == false ) mInputTab->setTabEnabled( 1, false );
}

void EncryptDlg::clearStatusLabel()
{
    mInitLabel->clear();
    mUpdateLabel->clear();
    mFinalLabel->clear();
}

void EncryptDlg::setStatusInit( int rv )
{
    clearStatusLabel();

    if( rv == CKR_OK )
        mInitLabel->setText( "Init OK" );
    else
        mInitLabel->setText( QString( "Init Fail:%1" ).arg( rv ) );
}

void EncryptDlg::setStatusUpdate( int rv, int count )
{
    if( rv == CKR_OK )
        mUpdateLabel->setText( QString( "|Update X %1" ).arg( count ) );
    else
        mUpdateLabel->setText( QString( "|Update Fail:%1").arg( rv ));
}

void EncryptDlg::setStatusFinal( int rv )
{
    if( rv == CKR_OK )
        mFinalLabel->setText( QString( "|Final OK" ) );
    else
        mFinalLabel->setText( QString( "|Final Fail:%1").arg( rv ));
}

void EncryptDlg::setStatusEncrypt( int rv )
{
    if( rv == CKR_OK )
        mFinalLabel->setText( QString( "|Encryt OK" ) );
    else
        mFinalLabel->setText( QString( "|Encryt Fail:%1").arg( rv ));
}


void EncryptDlg::keyTypeChanged( int index )
{
    mMechCombo->clear();

    if( mKeyTypeCombo->currentText() == sKeyList[0] )
    {
        mMechCombo->addItems(sMechEncSymList);
    }
    else if( mKeyTypeCombo->currentText() == sKeyList[1] )
    {
        mMechCombo->addItems(sMechEncAsymList);
    }

    mLabelText->clear();
    mObjectText->clear();
}

void EncryptDlg::inputChanged()
{
    QString strInput = mInputText->toPlainText();
    QString strLen = getDataLenString( mInputCombo->currentText(), strInput );
    mInputLenText->setText( QString("%1").arg( strLen ));
}

void EncryptDlg::outputChanged()
{
    QString strOutput = mOutputText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strOutput );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void EncryptDlg::paramChanged()
{
    QString strParam = mParamText->text();
    QString strLen = getDataLenString( DATA_HEX, strParam );
    mParamLenText->setText( QString("%1").arg(strLen));
}

void EncryptDlg::aadChanged()
{
    QString strAAD = mAADText->text();
    QString strLen = getDataLenString( mAADTypeCombo->currentText(), strAAD );
    mAADLenText->setText( QString("%1").arg(strLen));
}

void EncryptDlg::oaepSourceChanged()
{
    QString strSrc = mOAEPSourceText->text();
    QString strLen = getDataLenString( DATA_HEX, strSrc );
    mOAEPSourceLenText->setText( QString("%1").arg(strLen));
}

void EncryptDlg::clickInputClear()
{
    mInputText->clear();
}

void EncryptDlg::clickOutputClear()
{
    mOutputText->clear();
}

void EncryptDlg::clickFindSrcFile()
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
        mEncProgBar->setValue(0);

        QString strDstName = QString( "%1/%2_enc.bin" ).arg( fileInfo.absolutePath() ).arg( fileInfo.baseName() );

        mDstFileText->setText( strDstName );

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
        mDstFileInfoText->clear();
        mDstFileSizeText->clear();
    }
}

void EncryptDlg::clickFindDstFile()
{
    int nType = JS_FILE_TYPE_BIN;
    QString strPath = mDstFileText->text();

    QString fileName = manApplet->findSaveFile( this, nType, strPath );

    if( fileName.length() > 0 ) mDstFileText->setText( fileName );
}

int EncryptDlg::clickInit()
{
    int rv = -1;
    CK_MECHANISM sMech;
    update_cnt_ = 0;

    if( mObjectText->text().isEmpty() )
    {
        clickSelect();
        if( mObjectText->text().isEmpty() )
        {
            manApplet->warningBox( tr( "Select your key"), this );
            return -1;
        }
    }

    long hObject = mObjectText->text().toLong();

    setMechanism( &sMech );

    rv = manApplet->cryptokiAPI()->EncryptInit( slot_info_.getSessionHandle(), &sMech, hObject );

    setStatusInit(rv);

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("EncryptInit execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    status_type_ = STATUS_INIT;
    mOutputText->setPlainText( "" );

    freeMechanism( &sMech );

    return rv;
}

void EncryptDlg::clickUpdate()
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

    if( mInputCombo->currentIndex() == 0 )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length());
    else if( mInputCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    unsigned char *pEncPart = NULL;
    long uEncPartLen = binInput.nLen + 64;

    pEncPart = (unsigned char *)JS_malloc( binInput.nLen + 64 );
    if( pEncPart == NULL ) return;

    rv = manApplet->cryptokiAPI()->EncryptUpdate( slot_info_.getSessionHandle(), binInput.pVal, binInput.nLen, pEncPart, (CK_ULONG_PTR)&uEncPartLen );

    if( rv != CKR_OK )
    {
        setStatusUpdate( rv, update_cnt_ );
        mOutputText->setPlainText("");
        if( pEncPart ) JS_free( pEncPart );
        manApplet->warningBox( tr("EncryptUpdate execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    BIN binPart = {0,0};
    JS_BIN_set( &binPart, pEncPart, uEncPartLen );

    update_cnt_++;
    setStatusUpdate( rv, update_cnt_ );
    status_type_ = STATUS_UPDATE;
    mOutputText->appendPlainText( getHexString( binPart.pVal, binPart.nLen ));

    if( pEncPart ) JS_free( pEncPart );
    JS_BIN_reset( &binPart );
}

int EncryptDlg::clickFinal()
{
    int rv = -1;

    BIN binEncPart = {0,0};
    unsigned char sEnc[1024];
    long uEncLen = 1024;

    rv = manApplet->cryptokiAPI()->EncryptFinal( slot_info_.getSessionHandle(), sEnc, (CK_ULONG_PTR)&uEncLen );
    setStatusFinal(rv);

    if( rv != CKR_OK )
    {
        status_type_ = STATUS_NONE;
        mOutputText->setPlainText( "" );
        manApplet->warningBox( tr("EncryptFinal execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    JS_BIN_set( &binEncPart, sEnc, uEncLen );
    status_type_ = STATUS_FINAL;

    if( mInputTab->currentIndex() == 0 )
    {
        QString strOutput = getStringFromBIN( &binEncPart, DATA_HEX );
        mOutputText->appendPlainText( strOutput );
    }
    else
    {
        QString strDstPath = mDstFileText->text();
        JS_BIN_fileAppend( &binEncPart, strDstPath.toLocal8Bit().toStdString().c_str() );
    }

    JS_BIN_reset( &binEncPart );

    return rv;
}

void EncryptDlg::clickEncrypt()
{
    int index = mInputTab->currentIndex();

    if( index == 0 )
        runDataEncrypt();
    else
    {
        if( manApplet->isLicense() == false )
        {
            QString strMsg = tr( "This feature requires a license." );
            manApplet->warningBox( strMsg, this );
            return;
        }

        if( mRunThreadCheck->isChecked() )
            runFileEncryptThread();
        else
            runFileEncrypt();
    }
}

void EncryptDlg::runDataEncrypt()
{
    int rv = -1;

    QString strInput = mInputText->toPlainText();
/*
    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr( "Enter your data"), this );
        mInputText->setFocus();
        return;
    }
*/
    if( mInitAutoCheck->isChecked() )
    {
        rv = clickInit();
        if( rv != CKR_OK ) return;
    }

    BIN binInput = {0,0};

    if( mInputCombo->currentIndex() == 0 )
        JS_BIN_set( &binInput, (unsigned char *)strInput.toStdString().c_str(), strInput.length());
    else if( mInputCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    else if( mInputCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binInput );

    unsigned char *pEncData = NULL;
    long uEncDataLen = 0;
    BIN binEncData = {0,0};

    rv = manApplet->cryptokiAPI()->Encrypt( slot_info_.getSessionHandle(), binInput.pVal, binInput.nLen, NULL, (CK_ULONG_PTR)&uEncDataLen );
    setStatusEncrypt(rv);

    if( rv != CKR_OK )
    {
        status_type_ = STATUS_NONE;
        mOutputText->setPlainText( "" );
        manApplet->warningBox( tr("Encrypt execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    pEncData = (unsigned char *)JS_malloc( uEncDataLen );
    if( pEncData == NULL ) return;

    rv = manApplet->cryptokiAPI()->Encrypt( slot_info_.getSessionHandle(), binInput.pVal, binInput.nLen, pEncData, (CK_ULONG_PTR)&uEncDataLen );
    setStatusEncrypt(rv);

    if( rv != CKR_OK )
    {
        status_type_ = STATUS_NONE;
        mOutputText->setPlainText( "" );
        if( pEncData ) JS_free( pEncData );
        manApplet->warningBox( tr("Encrypt execution failure2 [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    status_type_ = STATUS_FINAL;

    char *pHex = NULL;
    JS_BIN_set( &binEncData, pEncData, uEncDataLen );
    JS_BIN_encodeHex( &binEncData, &pHex );
    mOutputText->setPlainText( pHex );

    if( pEncData ) JS_free( pEncData );
    if( pHex ) JS_free(pHex);
    JS_BIN_reset( &binEncData );
}

void EncryptDlg::runFileEncrypt()
{
    int rv = -1;

    int nRead = 0;
    int nPartSize = manApplet->settingsMgr()->fileReadSize();
    qint64 nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;
    int nPercent = 0;

    QString strSrcFile = mSrcFileText->text();
    BIN binPart = {0,0};
    BIN binDst = {0,0};

    if( strSrcFile.length() < 1)
    {
        manApplet->warningBox( tr( "Find source file"), this );
        mSrcFileText->setFocus();
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mEncProgBar->setValue( 0 );
    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    nLeft = fileSize;
    QString strDstFile = mDstFileText->text();
    if( strDstFile.length() < 1 )
    {
        manApplet->warningBox( tr( "Find destination file"), this );
        mDstFileText->setFocus();
        return;
    }

    if( QFile::exists( strDstFile ) )
    {
        QString strMsg = tr( "Destination file[%1] is already exist.\nDo you want to delete the file and continue?" ).arg( strDstFile );
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
        unsigned char *pEncPart = NULL;
        long uEncPartLen = 0;

        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 )
        {
            manApplet->warnLog( tr( "fail to read file: %1").arg( nRead ), this );
            goto end;
        }

        uEncPartLen = binPart.nLen + 64;

        pEncPart = (unsigned char *)JS_malloc( binPart.nLen + 64 );
        if( pEncPart == NULL ) return;

        rv = manApplet->cryptokiAPI()->EncryptUpdate( slot_info_.getSessionHandle(), binPart.pVal, binPart.nLen, pEncPart, (CK_ULONG_PTR)&uEncPartLen );

        if( rv != CKR_OK )
        {
            setStatusUpdate( rv, update_cnt_ );
            if( pEncPart ) JS_free( pEncPart );
            manApplet->warningBox( tr("EncryptUpdate execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
            goto end;
        }

        update_cnt_++;
        setStatusUpdate( rv, update_cnt_ );
        status_type_ = STATUS_UPDATE;

        if( uEncPartLen > 0 )
        {
            JS_BIN_set( &binDst, pEncPart, uEncPartLen );
            JS_free( pEncPart );
            pEncPart = NULL;
            uEncPartLen = 0;
        }

        if( binDst.nLen > 0 )
        {
            rv = JS_BIN_fileAppend( &binDst, strDstFile.toLocal8Bit().toStdString().c_str() );
            if( rv != binDst.nLen )
            {
                manApplet->warnLog( tr( "fail to append file: %1" ).arg( rv ), this );
                goto end;
            }

            rv = 0;
        }

        nReadSize += nRead;
        nPercent = int( ( nReadSize * 100 ) / fileSize );

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mEncProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        JS_BIN_reset( &binDst );
        update();
    }

    fclose( fp );
    manApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mEncProgBar->setValue( 100 );

        if( rv == 0 )
        {   
            rv = clickFinal();
            if( rv == 0 )
            {
                manApplet->messageLog( tr( "File(%1) save was successful" ).arg( strDstFile ), this );
            }

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

void EncryptDlg::clickClose()
{
    this->hide();
}

void EncryptDlg::clickSelect()
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
    {
        hsmMan.setMode( HsmModeSelectSecretKey, HsmUsageEncrypt );
    }
    else
    {
        hsmMan.mPublicTypeCombo->setCurrentText( "CKK_RSA" );
        hsmMan.setMode( HsmModeSelectPublicKey, HsmUsageEncrypt );
    }

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

void EncryptDlg::clickObjectView()
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

void EncryptDlg::runFileEncryptThread()
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

void EncryptDlg::startTask()
{
    if( thread_ != nullptr ) delete thread_;

    thread_ = new EncryptThread;

    QString strSrcFile = mSrcFileText->text();

    if( strSrcFile.length() < 1)
    {
        manApplet->warningBox( tr( "Find source file"), this );
        mSrcFileText->setFocus();
        return;
    }

    QString strDstFile = mDstFileText->text();
    if( strDstFile.length() < 1 )
    {
        manApplet->warningBox( tr( "Find destination file"), this );
        mDstFileText->setFocus();
        return;
    }

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

    connect(thread_, &EncryptThread::taskFinished, this, &EncryptDlg::onTaskFinished);
    connect( thread_, &EncryptThread::taskUpdate, this, &EncryptDlg::onTaskUpdate);

    thread_->setSession( slot_info_.getSessionHandle() );
    thread_->setSrcFile( strSrcFile );
    thread_->setDstFile( strDstFile );
    thread_->start();
}

void EncryptDlg::onTaskFinished()
{
    manApplet->log("Task finished");

    clickFinal();

    QString strDstFile = mDstFileText->text();
    QFileInfo fileInfo;
    fileInfo.setFile( strDstFile );
    qint64 fileSize = fileInfo.size();
    QDateTime cTime = fileInfo.lastModified();

    QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));
    mDstFileSizeText->setText( QString("%1").arg( fileSize ));
    mDstFileInfoText->setText( strInfo );

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void EncryptDlg::onTaskUpdate( qint64 nUpdate )
{
    manApplet->log( QString("Update: %1").arg( nUpdate ));
    qint64 nFileSize = mFileTotalSizeText->text().toLongLong();
    int nPercent = int( (nUpdate * 100) / nFileSize );
    update_cnt_++;
    setStatusUpdate( CKR_OK, update_cnt_ );
    status_type_ = STATUS_UPDATE;

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mEncProgBar->setValue( nPercent );
}
