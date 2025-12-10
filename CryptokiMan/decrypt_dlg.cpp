/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileInfo>
#include <QDateTime>
#include <QFileDialog>

#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

#include "decrypt_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"
#include "settings_mgr.h"
#include "mech_mgr.h"
#include "decrypt_thread.h"
#include "hsm_man_dlg.h"
#include "object_view_dlg.h"

#include "js_error.h"


static QStringList sKeyList = { "SECRET", "PRIVATE" };
static QStringList sMechEncSymList;
static QStringList sMechEncAsymList;

DecryptDlg::DecryptDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;

    update_cnt_ = 0;
    thread_ = NULL;

    setupUi(this);
    setAcceptDrops( true );
    initUI();

    mDecryptBtn->setDefault(true);
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

DecryptDlg::~DecryptDlg()
{
    if( thread_ ) delete thread_;

    if( status_type_ == STATUS_INIT || status_type_ == STATUS_UPDATE )
        resetFinal();
}

void DecryptDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void DecryptDlg::dropEvent(QDropEvent *event)
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
        sMechEncSymList = kMechEncSymList;
        sMechEncAsymList = kMechEncAsymList;
    }

    mInputText->setPlaceholderText( tr("Hex value" ));

    mKeyTypeCombo->addItems(sKeyList);
    mMechCombo->addItems( sMechEncSymList );
    mOutputCombo->addItems( kDataTypeList );
    mAADTypeCombo->addItems( kDataTypeList );
    mOAEPHashAlgCombo->addItems( kMechSHAList );
    mOAEPMgfCombo->addItems( kMGFList );

    mRunThreadCheck->setChecked(true);

    setLineEditHexOnly( mOAEPSourceText, tr("Hex value") );
    setLineEditHexOnly( mParamText, tr("Hex value"));

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));

    connect( mResetBtn, SIGNAL(clicked(bool)), this, SLOT(clickReset()));
    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mDecryptBtn, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));
    connect( mSelectBtn, SIGNAL(clicked()), this, SLOT(clickSelect()));

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
    connect( mObjectViewBtn, SIGNAL(clicked()), this, SLOT(clickObjectView()));

    initialize();
    keyTypeChanged(0);

    mLabelText->setPlaceholderText( tr( "Select a key from HSM Man" ));
    mParamText->setPlaceholderText( tr( "Hex value" ));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

void DecryptDlg::setMechanism( void *pMech )
{
    int rv = -1;
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
        rv = getBINFromString( &binAAD, mAADTypeCombo->currentText(), strAAD );
        if( rv < 0 )
        {
            manApplet->formatWarn( rv, this );
            return;
        }

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
    else if( nMech == CKM_AES_CCM )
    {
        BIN binIV = {0,0};
        BIN binAAD = {0,0};

        int nReqLen = mReqTagLenText->text().toInt();
        int nSrcLen = mSrcLengthText->text().toInt();

        QString strIV = mParamText->text();
        QString strAAD = mAADText->text();

        JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
        rv = getBINFromString( &binAAD, mAADTypeCombo->currentText(), strAAD );
        if( rv < 0 )
        {
            manApplet->formatWarn( rv, this );
            return;
        }

        CK_CCM_PARAMS_PTR ccmParam;
        ccmParam->ulDataLen = nSrcLen;
        ccmParam->pNonce = binIV.pVal;
        ccmParam->ulNonceLen = binIV.nLen;
        ccmParam->pAAD = binAAD.pVal;
        ccmParam->ulAADLen = binAAD.nLen;
        ccmParam->ulMACLen = nReqLen;

        pPtr->pParameter = ccmParam;
        pPtr->ulParameterLen = sizeof(CK_CCM_PARAMS);
    }
    else if( nMech == CKM_RSA_PKCS_OAEP )
    {
        BIN binSrc = {0,0};
        CK_RSA_PKCS_OAEP_PARAMS *pOAEPParam = NULL;
        QString strHashAlg = mOAEPHashAlgCombo->currentText();
        QString strMgf = mOAEPMgfCombo->currentText();
        QString strSrc = mOAEPSourceText->text();

        pOAEPParam = (CK_RSA_PKCS_OAEP_PARAMS *)JS_calloc( 1, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
        rv = getBINFromString( &binSrc, DATA_HEX, strSrc.toStdString().c_str() );
        if( rv < 0 )
        {
            manApplet->formatWarn( rv, this );
            return;
        }

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

void DecryptDlg::freeMechanism( void *pMech )
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

void DecryptDlg::mechChanged( int index )
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

void DecryptDlg::clickObjectView()
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

void DecryptDlg::setSlotIndex(int index)
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

    manApplet->cryptokiAPI()->GetAttributeValue2( slot_info_.getSessionHandle(), hObj, CKA_LABEL, &binVal );
    JS_BIN_string( &binVal, &pLabel );
    JS_BIN_reset( &binVal );

    mLabelText->setText( pLabel );
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
    status_type_ = STATUS_NONE;
    mOutputCombo->setCurrentText( "Hex" );

    clearStatusLabel();

    if( manApplet->isLicense() == false ) mInputTab->setTabEnabled( 1, false );
}

void DecryptDlg::setSrcFileInfo( const QString strFile )
{
    if( strFile.length() > 0 )
    {
        QFileInfo fileInfo;
        fileInfo.setFile( strFile );
        QString strMode;

        qint64 fileSize = fileInfo.size();
        QDateTime cTime = fileInfo.lastModified();

        QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));

        mSrcFileText->setText( strFile );
        mSrcFileSizeText->setText( QString("%1").arg( fileSize ));
        mSrcFileInfoText->setText( strInfo );
        mDecProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
        mDstFileInfoText->clear();
        mDstFileSizeText->clear();
    }
}

void DecryptDlg::clearStatusLabel()
{
    mStatusLabel->setText( "Status" );
    mInitText->clear();
    mUpdateText->clear();
    mFinalText->clear();
}

void DecryptDlg::setStatusInit( int rv )
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

void DecryptDlg::setStatusUpdate( int rv, int count )
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

void DecryptDlg::setStatusFinal( int rv )
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

void DecryptDlg::setStatusDecrypt( int rv )
{
    if( rv == CKR_OK )
    {
        mStatusLabel->setText( QString( "Decrypt OK" ) );
    }
    else
    {
        mStatusLabel->setText( QString( "%1").arg( P11ERR(rv) ));
    }
}

void DecryptDlg::keyTypeChanged( int index )
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

void DecryptDlg::inputChanged()
{
    QString strInput = mInputText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strInput );
    mInputLenText->setText( QString("%1").arg( strLen ));
}

void DecryptDlg::outputChanged()
{
    QString strOutput = mOutputText->toPlainText();
    QString strLen = getDataLenString( mOutputCombo->currentText(), strOutput );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void DecryptDlg::paramChanged()
{
    QString strParam = mParamText->text();
    QString strLen = getDataLenString( DATA_HEX, strParam );
    mParamLenText->setText( QString("%1").arg(strLen));
}

void DecryptDlg::aadChanged()
{
    QString strAAD = mAADText->text();
    QString strLen = getDataLenString( mAADTypeCombo->currentText(), strAAD );
    mAADLenText->setText( QString("%1").arg(strLen));
}

void DecryptDlg::oaepSourceChanged()
{
    QString strSrc = mOAEPSourceText->text();
    QString strLen = getDataLenString( DATA_HEX, strSrc );
    mOAEPSourceLenText->setText( QString("%1").arg(strLen));
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
        mDecProgBar->setValue(0);

        QString strDstName = QString( "%1/%2_dec.bin" ).arg( fileInfo.absolutePath() ).arg( fileInfo.baseName() );

        mDstFileText->setText( strDstName );

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
        mDstFileInfoText->clear();
        mDstFileSizeText->clear();
    }
}

void DecryptDlg::clickFindDstFile()
{
    int nType = JS_FILE_TYPE_BIN;
    QString strPath = mDstFileText->text();

    QString fileName = manApplet->findSaveFile( this, nType, strPath );

    if( fileName.length() > 0 ) mDstFileText->setText( fileName );
}

void DecryptDlg::clickReset()
{
    clearStatusLabel();

    mFileReadSizeText->clear();
    mFileTotalSizeText->clear();
    mDecProgBar->setValue(0);

    if( status_type_ == STATUS_INIT || status_type_ == STATUS_UPDATE )
        resetFinal();
}

int DecryptDlg::clickInit()
{
    int rv = -1;
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
    CK_MECHANISM sMech;

    memset( &sMech, 0x00, sizeof(sMech));

    setMechanism( &sMech );

    rv = manApplet->cryptokiAPI()->DecryptInit( slot_info_.getSessionHandle(), &sMech, hObject );
    setStatusInit( rv );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("DecryptInit execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );

        return rv;
    }

    mOutputText->setPlainText("");
    status_type_ = STATUS_INIT;
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

    rv = getBINFromString( &binInput, DATA_HEX, strInput );
    if( rv < 0 )
    {
        manApplet->formatWarn( rv, this );
        return;
    }

    unsigned char *pDecPart = NULL;
    long uDecPartLen = binInput.nLen;

    pDecPart = (unsigned char *)JS_malloc( binInput.nLen );
    if( pDecPart == NULL ) return;

    BIN binDecPart = {0,0};

    rv = manApplet->cryptokiAPI()->DecryptUpdate( slot_info_.getSessionHandle(), binInput.pVal, binInput.nLen, pDecPart, (CK_ULONG_PTR)&uDecPartLen );

    if( rv != CKR_OK )
    {
        if( pDecPart ) JS_free( pDecPart );
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("DecryptUpdate execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this);
        setStatusUpdate( rv, update_cnt_ );
        return;
    }

    JS_BIN_set( &binDecPart, pDecPart, uDecPartLen );

    QString strDec = getStringFromBIN( &binDecPart, mOutputCombo->currentText() );
    mOutputText->appendPlainText( strDec );
    JS_BIN_reset( &binDecPart );

    status_type_ = STATUS_UPDATE;
    update_cnt_++;
    setStatusUpdate( rv, update_cnt_ );

    if( pDecPart ) JS_free( pDecPart );
}

void DecryptDlg::resetFinal()
{
    int rv = -1;

    unsigned char sDec[1024];
    long uDecLen = 1024;

    rv = manApplet->cryptokiAPI()->DecryptFinal( slot_info_.getSessionHandle(), sDec, (CK_ULONG_PTR)&uDecLen );

    if( rv != CKR_OK )
    {
        status_type_ = STATUS_NONE;
    }
    else
    {
        status_type_ = STATUS_FINAL;
    }
}

int DecryptDlg::clickFinal()
{
    int rv = -1;

    BIN binDecPart = {0,0};

    unsigned char sDec[1024];
    long uDecLen = 1024;

    rv = manApplet->cryptokiAPI()->DecryptFinal( slot_info_.getSessionHandle(), sDec, (CK_ULONG_PTR)&uDecLen );
    setStatusFinal(rv);

    if( rv != CKR_OK )
    {
        status_type_ = STATUS_NONE;
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("DecryptFinal execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    JS_BIN_set( &binDecPart, sDec, uDecLen );

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

    status_type_ = STATUS_FINAL;
    JS_BIN_reset( &binDecPart );

    return rv;
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

        if( mRunThreadCheck->isChecked() )
            runFileDecryptThread();
        else
            runFileDecrypt();
    }
}

void DecryptDlg::runDataDecrypt()
{
    int rv = -1;

    QString strInput = mInputText->toPlainText();

    /*
    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("Enter your data"), this );
        mInputText->setFocus();
        return;
    }
    */

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

    rv = getBINFromString( &binInput, DATA_HEX, strInput );
    if( rv < 0 )
    {
        manApplet->formatWarn( rv, this );
        return;
    }

    unsigned char *pDecData = NULL;
    long uDecDataLen = 0;

    rv = manApplet->cryptokiAPI()->Decrypt( slot_info_.getSessionHandle(), binInput.pVal, binInput.nLen, NULL, (CK_ULONG_PTR)&uDecDataLen );

    if( rv != CKR_OK )
    {
        status_type_ = STATUS_NONE;
        mOutputText->setPlainText( "" );
        manApplet->warningBox( tr("Decrypt execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        setStatusDecrypt(rv);
        return;
    }

    pDecData = (unsigned char *)JS_malloc( uDecDataLen );

    rv = manApplet->cryptokiAPI()->Decrypt( slot_info_.getSessionHandle(), binInput.pVal, binInput.nLen, pDecData, (CK_ULONG_PTR)&uDecDataLen );

    if( rv != CKR_OK )
    {
        status_type_ = STATUS_NONE;
        if( pDecData ) JS_free( pDecData );
        mOutputText->setPlainText( "" );
        manApplet->warningBox( tr("Decrypt execution failure2 [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        setStatusDecrypt(rv);
        return;
    }

    setStatusDecrypt(rv);

    BIN binDecData = {0,0};
    JS_BIN_set( &binDecData, pDecData, uDecDataLen );
    QString strDec = getStringFromBIN( &binDecData, mOutputCombo->currentText() );

    mOutputText->setPlainText( strDec );
    if( pDecData ) JS_free( pDecData );
    JS_BIN_reset( &binDecData );

    status_type_ = STATUS_FINAL;
}

void DecryptDlg::runFileDecrypt()
{
    int rv = -1;

    int nRead = 0;
    int nPartSize = manApplet->settingsMgr()->fileReadSize();
    qint64 nReadSize = 0;
    int nLeft = 0;
    qint64 nOffset = 0;
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

    mDecProgBar->setValue( 0 );
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
        if( nRead <= 0 )
        {
            manApplet->warnLog( tr( "fail to read file: %1").arg( nRead ), this );
            goto end;
        }

        uDecPartLen = binPart.nLen + 64;

        pDecPart = (unsigned char *)JS_malloc( binPart.nLen + 64 );
        if( pDecPart == NULL ) return;

        rv = manApplet->cryptokiAPI()->DecryptUpdate( slot_info_.getSessionHandle(), binPart.pVal, binPart.nLen, pDecPart, (CK_ULONG_PTR)&uDecPartLen );

        if( rv != CKR_OK )
        {
            if( pDecPart ) JS_free( pDecPart );
            setStatusUpdate( rv, update_cnt_ );
            manApplet->warningBox( tr("DecryptUpdate execution failure [%1]").arg(JS_PKCS11_GetErrorMsg(rv)), this );
            goto end;
        }

        update_cnt_++;
        status_type_ = STATUS_UPDATE;
        setStatusUpdate( rv, update_cnt_ );

        if( uDecPartLen > 0 )
        {
            JS_BIN_set( &binDst, pDecPart, uDecPartLen );
            JS_free( pDecPart );
            pDecPart = NULL;
            uDecPartLen = 0;
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
        mDecProgBar->setValue( nPercent );

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
        mDecProgBar->setValue( 100 );

        if( rv == 0 )
        {
            QString strMsg = QString( "|Update X %1").arg( update_cnt_ );
            setStatusUpdate( rv, update_cnt_ );
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

void DecryptDlg::clickClose()
{
    this->hide();
}

void DecryptDlg::clickSelect()
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
        hsmMan.setMode( HsmModeSelectSecretKey, HsmUsageDecrypt );
    }
    else
    {
        hsmMan.mPrivateTypeCombo->setCurrentText( "CKK_RSA" );
        hsmMan.setMode( HsmModeSelectPrivateKey, HsmUsageDecrypt );
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

void DecryptDlg::startTask()
{
    if( thread_ != nullptr ) delete thread_;

    thread_ = new DecryptThread;

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

    connect(thread_, &DecryptThread::taskFinished, this, &DecryptDlg::onTaskFinished);
    connect( thread_, &DecryptThread::taskUpdate, this, &DecryptDlg::onTaskUpdate);

    thread_->setSession( slot_info_.getSessionHandle() );
    thread_->setSrcFile( strSrcFile );
    thread_->setDstFile( strDstFile );
    thread_->start();
}

void DecryptDlg::onTaskFinished()
{
    manApplet->log("Task finished");


    QString strStatus = QString( "|Update X %1").arg( update_cnt_ );

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

void DecryptDlg::onTaskUpdate( qint64 nUpdate )
{
    manApplet->log( QString("Update: %1").arg( nUpdate ));
    qint64 nFileSize = mFileTotalSizeText->text().toLongLong();
    int nPercent = int( (nUpdate * 100) / nFileSize );
    update_cnt_++;
    setStatusUpdate( CKR_OK, update_cnt_ );
    status_type_ = STATUS_UPDATE;

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mDecProgBar->setValue( nPercent );
}
