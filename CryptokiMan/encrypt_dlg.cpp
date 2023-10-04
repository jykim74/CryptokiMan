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

static QStringList sKeyList = { "SECRET", "PUBLIC" };

static QStringList sMechEncSymList;
static QStringList sMechEncAsymList;

EncryptDlg::EncryptDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    session_ = -1;

    setupUi(this);
    initUI();
#if defined(Q_OS_MAC)
    layout()->setSpacing(3);
#endif
}

EncryptDlg::~EncryptDlg()
{

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
        sMechEncSymList = kMechEncSymNoLicenseList;
        sMechEncAsymList = kMechEncAsymList;
    }

    mKeyTypeCombo->addItems(sKeyList);
    mMechCombo->addItems( sMechEncSymList );
    mInputCombo->addItems( kDataTypeList );
    mAADTypeCombo->addItems( kDataTypeList );

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));
    connect( mLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(labelChanged(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mEncryptBtn, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));

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
}

void EncryptDlg::setMechanism( void *pMech )
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

void EncryptDlg::freeMechanism( void *pMech )
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

void EncryptDlg::slotChanged(int index)
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

void EncryptDlg::mechChanged( int index )
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

void EncryptDlg::setSelectedSlot(int index)
{
    slotChanged(index);

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

    manApplet->cryptokiAPI()->GetAttributeValue2( session_, hObj, CKA_LABEL, &binVal );
    JS_BIN_string( &binVal, &pLabel );
    JS_BIN_reset( &binVal );

    mLabelCombo->setCurrentText( pLabel );
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
}

void EncryptDlg::appendStatusLabel( const QString& strLabel )
{
    QString strStatus = mStatusLabel->text();
    strStatus += strLabel;
    mStatusLabel->setText( strStatus );
}

void EncryptDlg::keyTypeChanged( int index )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[10];
    CK_ULONG uCnt = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
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
        objClass = CKO_PUBLIC_KEY;
        mMechCombo->addItems(sMechEncAsymList);
    }

    if( session_ < 0 ) return;

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    sTemplate[uCnt].type = CKA_ENCRYPT;
    sTemplate[uCnt].pValue = &kTrue;
    sTemplate[uCnt].ulValueLen = sizeof(CK_BBOOL);
    uCnt++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( session_, sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( session_, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal(session_);
    if( rv != CKR_OK ) return;

    if( mLabelCombo->count() > 0 ) mLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char    *pStr = NULL;
        BIN binLabel = {0,0};

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( session_, sObjects[i], CKA_LABEL, &binLabel );
        if( rv != CKR_OK ) break;

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

void EncryptDlg::labelChanged( int index )
{
    QVariant objVal = mLabelCombo->itemData( index );

    QString strHandle = QString("%1").arg( objVal.toInt() );

    mObjectText->setText( strHandle );
}

void EncryptDlg::inputChanged()
{
    QString strInput = mInputText->toPlainText();
    int nLen = getDataLen( mInputCombo->currentText(), strInput );
    mInputLenText->setText( QString("%1").arg( nLen ));
}

void EncryptDlg::outputChanged()
{
    QString strOutput = mOutputText->toPlainText();
    int nLen = getDataLen( DATA_HEX, strOutput );
    mOutputLenText->setText( QString("%1").arg(nLen));
}

void EncryptDlg::paramChanged()
{
    QString strParam = mParamText->text();
    int nLen = getDataLen( DATA_HEX, strParam );
    mParamLenText->setText( QString("%1").arg(nLen));
}

void EncryptDlg::aadChanged()
{
    QString strAAD = mAADText->text();
    int nLen = getDataLen( mAADTypeCombo->currentText(), strAAD );
    mAADLenText->setText( QString("%1").arg(nLen));
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
        mEncProgBar->setValue(0);

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

void EncryptDlg::clickFindDstFile()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strFilter;
    QString strPath = mDstFileText->text();

    QString selectedFilter;
    QString fileName = QFileDialog::getSaveFileName( this,
                                                     tr("Encrypt Files"),
                                                     strPath,
                                                     strFilter,
                                                     &selectedFilter,
                                                     options );

    if( fileName.length() > 0 ) mDstFileText->setText( fileName );
}

int EncryptDlg::clickInit()
{
    int rv = -1;

    CK_MECHANISM sMech;


    long hObject = mObjectText->text().toLong();
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
    rv = manApplet->cryptokiAPI()->EncryptInit( session_, &sMech, hObject );

    if( rv != CKR_OK )
    {
        mStatusLabel->setText("");
        mOutputText->setPlainText("");
        manApplet->warningBox( tr("fail to run EncryptInit(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return rv;
    }

    mStatusLabel->setText( "Init" );
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
        manApplet->warningBox( tr("You have to insert data."), this );
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

    rv = manApplet->cryptokiAPI()->EncryptUpdate( session_, binInput.pVal, binInput.nLen, pEncPart, (CK_ULONG_PTR)&uEncPartLen );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText("");
        if( pEncPart ) JS_free( pEncPart );
        manApplet->warningBox( tr("fail to run EncryptUpdate(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    BIN binPart = {0,0};
    JS_BIN_set( &binPart, pEncPart, uEncPartLen );
    appendStatusLabel( "|Update" );

    mOutputText->appendPlainText( getHexString( binPart.pVal, binPart.nLen ));

    if( pEncPart ) JS_free( pEncPart );
    JS_BIN_reset( &binPart );
}

void EncryptDlg::clickFinal()
{
    int rv = -1;

    unsigned char *pEncPart = NULL;
    long uEncPartLen = 0;

    BIN binEncPart = {0,0};

    rv = manApplet->cryptokiAPI()->EncryptFinal( session_, NULL, (CK_ULONG_PTR)&uEncPartLen );
    if( rv != CKR_OK )
    {
        mOutputText->setPlainText( "" );
        if( pEncPart ) JS_free( pEncPart );
        manApplet->warningBox( tr("fail to run EncryptFinal(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    if( uEncPartLen > 0 )
    {
        pEncPart = (unsigned char *)JS_malloc( uEncPartLen );
        if( pEncPart == NULL ) return;
    }

    rv = manApplet->cryptokiAPI()->EncryptFinal( session_, pEncPart, (CK_ULONG_PTR)&uEncPartLen );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText( "" );
        if( pEncPart ) JS_free( pEncPart );
        manApplet->warningBox( tr("fail to run EncryptFinal(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }


    JS_BIN_set( &binEncPart, pEncPart, uEncPartLen );

    appendStatusLabel( "|Final" );


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

    if( pEncPart ) JS_free( pEncPart );
    JS_BIN_reset( &binEncPart );
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

        runFileEncrypt();
    }
}

void EncryptDlg::runDataEncrypt()
{
    int rv = -1;

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr( "You have to insert data."), this );
        mInputText->setFocus();
        return;
    }

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
    long uEncDataLen = binInput.nLen + 64;
    BIN binEncData = {0,0};

    pEncData = (unsigned char *)JS_malloc( binInput.nLen + 64 );
    if( pEncData == NULL ) return;

    rv = manApplet->cryptokiAPI()->Encrypt( session_, binInput.pVal, binInput.nLen, pEncData, (CK_ULONG_PTR)&uEncDataLen );

    if( rv != CKR_OK )
    {
        mOutputText->setPlainText( "" );
        if( pEncData ) JS_free( pEncData );
        manApplet->warningBox( tr("fail to run Encrypt(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        return;
    }

    char *pHex = NULL;
    JS_BIN_set( &binEncData, pEncData, uEncDataLen );
    JS_BIN_encodeHex( &binEncData, &pHex );
    mOutputText->setPlainText( pHex );
    QString strRes = mStatusLabel->text();
    strRes += "|Encrypt";
    mStatusLabel->setText( strRes );

    if( pEncData ) JS_free( pEncData );
    if( pHex ) JS_free(pHex);
    JS_BIN_reset( &binEncData );
}

void EncryptDlg::runFileEncrypt()
{
    int rv = -1;

    int nRead = 0;
    int nPartSize = manApplet->settingsMgr()->fileReadSize();
    int nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;
    int nPercent = 0;
    int nUpdateCnt = 0;
    QString strSrcFile = mSrcFileText->text();
    BIN binPart = {0,0};
    BIN binDst = {0,0};

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mEncProgBar->setValue( 0 );
    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    nLeft = fileSize;
    QString strDstFile = mDstFileText->text();

    if( QFile::exists( strDstFile ) )
    {
        QString strMsg = tr( "Dst file[%1] is already exist.\nDo you want to delete the file and continue?" ).arg( strDstFile );
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
        manApplet->elog( QString( "fail to read file:%1").arg( strSrcFile ));
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
        if( nRead <= 0 ) break;

        if( mWriteLogCheck->isChecked() )
        {
            manApplet->log( QString( "Read[%1:%2] %3").arg( nOffset ).arg( nRead ).arg( getHexString(binPart.pVal, binPart.nLen)));
        }

        uEncPartLen = binPart.nLen + 64;

        pEncPart = (unsigned char *)JS_malloc( binPart.nLen + 64 );
        if( pEncPart == NULL ) return;

        rv = manApplet->cryptokiAPI()->EncryptUpdate( session_, binPart.pVal, binPart.nLen, pEncPart, (CK_ULONG_PTR)&uEncPartLen );

        if( rv != CKR_OK )
        {
            if( pEncPart ) JS_free( pEncPart );
            manApplet->warningBox( tr("fail to run EncryptUpdate(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
            goto end;
        }



        nUpdateCnt++;

        if( uEncPartLen > 0 )
        {
            JS_BIN_set( &binDst, pEncPart, uEncPartLen );
            JS_free( pEncPart );
            pEncPart = NULL;
            uEncPartLen = 0;
        }

        if( mWriteLogCheck->isChecked() )
        {
            manApplet->log( QString( "Enc[%1:%2] %3").arg( nOffset ).arg( binDst.nLen ).arg( getHexString(binDst.pVal, binDst.nLen)));
        }

        if( binDst.nLen > 0 )
            JS_BIN_fileAppend( &binDst, strDstFile.toLocal8Bit().toStdString().c_str() );

        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mEncProgBar->setValue( nPercent );

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
        mEncProgBar->setValue( 100 );

        if( rv == 0 )
        {
            QString strMsg = QString( "|Update X %1").arg( nUpdateCnt );
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

void EncryptDlg::clickClose()
{
    this->hide();
}
