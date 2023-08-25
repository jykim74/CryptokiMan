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

static QStringList sMechDigestList;

static QStringList sInputList = {
    "String", "Hex", "Base64"
};

DigestDlg::DigestDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
    initialize();
}

DigestDlg::~DigestDlg()
{

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

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT( slotChanged(int) ));
    connect( mKeyLabelCombo, SIGNAL(currentIndexChanged(int)), this, SLOT( changeKeyLabel(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(clickInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(clickFinal()));
    connect( mDigestKeyBtn, SIGNAL(clicked()), this, SLOT(clickDigestKey()));
    connect( mDigestBtn, SIGNAL(clicked()), this, SLOT(clickDigest()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged(const QString&)), this, SLOT(outputChanged()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));
    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(3);
#endif
}

long DigestDlg::getSessionHandle()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    return hSession;
}

void DigestDlg::setKeyList()
{
    int rv = -1;

    CK_SESSION_HANDLE hSession = getSessionHandle();

    CK_ATTRIBUTE sTemplate[1];
    CK_ULONG uCnt = 0;
    CK_OBJECT_HANDLE sObjects[20];
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = 0;

    CK_OBJECT_CLASS objClass = 0;

    objClass = CKO_SECRET_KEY;

    sTemplate[uCnt].type = CKA_CLASS;
    sTemplate[uCnt].pValue = &objClass;
    sTemplate[uCnt].ulValueLen = sizeof(objClass);
    uCnt++;

    rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, sTemplate, uCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( hSession, sObjects, uMaxObjCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
    if( rv != CKR_OK ) return;

    mKeyLabelCombo->clear();

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;

        BIN binLabel = {0,0};
        QVariant objVal = QVariant( (int)sObjects[i] );

        rv = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, sObjects[i], CKA_LABEL, &binLabel );

        JS_BIN_string( &binLabel, &pLabel );

        mKeyLabelCombo->addItem( pLabel, objVal );

        if( pLabel ) JS_free( pLabel );
        JS_BIN_reset( &binLabel );
    }
}

void DigestDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void DigestDlg::changeKeyLabel( int index )
{
    QVariant objVal = mKeyLabelCombo->itemData(index);

    QString strObject = QString("%1").arg( objVal.toInt() );
    mKeyObjectText->setText( strObject );
}

void DigestDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);

    setKeyList();
}


void DigestDlg::initialize()
{
    mSlotsCombo->clear();

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    for( int i=0; i < slot_infos.size(); i++ )
    {
        SlotInfo slotInfo = slot_infos.at(i);

        mSlotsCombo->addItem( slotInfo.getDesc() );
    }

    if( slot_infos.size() > 0 ) slotChanged(0);

    mInitAutoCheck->setChecked(true);
    mInputTab->setCurrentIndex(0);
}

void DigestDlg::appendStatusLabel( const QString& strLabel )
{
    QString strStatus = mStatusLabel->text();
    strStatus += strLabel;
    mStatusLabel->setText( strStatus );
}

void DigestDlg::clickDigestKey()
{
    int rv;
    CK_SESSION_HANDLE hSession = getSessionHandle();
    CK_OBJECT_HANDLE hKey = mKeyObjectText->text().toULong();

    rv = manApplet->cryptokiAPI()->DigestKey( hSession, hKey );

    if( rv == CKR_OK )
    {
        QString strMsg = mStatusLabel->text();
        strMsg += "|DigestKey";

        mStatusLabel->setText( strMsg );
    }
    else
    {
        manApplet->warningBox( tr("fail to run DigestKey(%1)").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        mOutputText->setText("");
    }
}

int DigestDlg::clickInit()
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = getSessionHandle();

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

    rv = manApplet->cryptokiAPI()->DigestInit( hSession, &stMech );

    if( rv == CKR_OK )
    {
        mStatusLabel->setText( "Init" );
        mOutputText->setText( "" );
    }
    else
    {
        manApplet->warningBox( tr("fail to run DigestInit(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        mStatusLabel->setText("");
        mOutputText->setText("");
    }

    return rv;
}

void DigestDlg::clickUpdate()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    QString strInput = mInputText->toPlainText();
    if( strInput.isEmpty() )
    {
        manApplet->warningBox(tr("Insert input value."), this );
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

    rv = manApplet->cryptokiAPI()->DigestUpdate( hSession, binInput.pVal, binInput.nLen );

    if( rv == CKR_OK )
    {
        appendStatusLabel( "|Update" );
    }
    else
    {
        manApplet->warningBox( tr("fail to run DigestUpdate(%1)").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        mOutputText->setText("");
    }
}

void DigestDlg::clickFinal()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();


    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();


    unsigned char sDigest[512];
    CK_ULONG uDigestLen = 64;
    BIN binDigest = {0,0};

    memset( sDigest, 0x00, sizeof(sDigest) );

    rv = manApplet->cryptokiAPI()->DigestFinal( hSession, sDigest, &uDigestLen );

    if( rv == CKR_OK )
    {
        JS_BIN_set( &binDigest, sDigest, uDigestLen );
        mOutputText->setText( getHexString( binDigest.pVal, binDigest.nLen) );
        appendStatusLabel( "|Final" );
    }
    else
    {
        manApplet->warningBox( tr("fail to run DigestFinal(%1)").arg(JS_PKCS11_GetErrorMsg(rv)), this );
        mOutputText->setText("");
    }

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

        runFileDigest();
    }
}

void DigestDlg::runDataDigest()
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = getSessionHandle();

    QString strInput = mInputText->toPlainText();
    if( strInput.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert input value"), this );
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

    rv = manApplet->cryptokiAPI()->Digest( hSession, binInput.pVal, binInput.nLen, sDigest, &uDigestLen );

    if( rv == CKR_OK )
    {
        char *pHex = NULL;
        JS_BIN_set( &binDigest, sDigest, uDigestLen );
        JS_BIN_encodeHex( &binDigest, &pHex );
        mOutputText->setText( pHex );

        QString strRes = mStatusLabel->text();
        strRes += "|Digest";
        mStatusLabel->setText(strRes);
    }
    else
    {
        manApplet->warningBox( tr("fail run Digest(%1)").arg( JS_PKCS11_GetErrorMsg(rv)), this );
        mOutputText->setText("");
    }
}

void DigestDlg::runFileDigest()
{
    int ret = -1;
    CK_SESSION_HANDLE hSession = getSessionHandle();

    int nRead = 0;
    int nPartSize = manApplet->settingsMgr()->fileReadSize();
    int nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;
    int nPercent = 0;
    int nUpdateCnt = 0;
    QString strSrcFile = mSrcFileText->text();
    BIN binPart = {0,0};

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
            manApplet->warningBox( tr("fail to initialize digest:%1").arg(ret), this );
            return;
        }
    }

    FILE *fp = fopen( strSrcFile.toLocal8Bit().toStdString().c_str(), "rb" );

    if( fp == NULL )
    {
        manApplet->elog( QString( "fail to read file:%1").arg( strSrcFile ));
        goto end;
    }

    manApplet->log( QString( "TotalSize: %1 BlockSize: %2").arg( fileSize).arg( nPartSize ));


    while( nLeft > 0 )
    {
        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 ) break;

        if( mWriteLogCheck->isChecked() )
        {
            manApplet->log( QString( "Read[%1:%2] %3").arg( nOffset ).arg( nRead ).arg( getHexString(binPart.pVal, binPart.nLen)));
        }

        ret = manApplet->cryptokiAPI()->DigestUpdate( hSession, binPart.pVal, binPart.nLen );
        if( ret != CKR_OK )
        {
            manApplet->warningBox( tr("fail to run DigestUpdate(%1)").arg( JS_PKCS11_GetErrorMsg(ret)), this );
            goto end;
        }

        nUpdateCnt++;
        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mHashProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        repaint();
    }

    fclose( fp );
    manApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mHashProgBar->setValue( 100 );

        if( ret == CKR_OK )
        {
            QString strMsg = QString( "|Update X %1" ).arg( nUpdateCnt );
            appendStatusLabel( strMsg );
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
    int nLen = getDataLen( mInputCombo->currentText(), strInput );
    mInputLenText->setText( QString("%1").arg( nLen ));
}

void DigestDlg::outputChanged()
{
    QString strOutput = mOutputText->text();
    int nLen = getDataLen( DATA_HEX, strOutput );
    mOutputLenText->setText( QString("%1").arg(nLen));
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
    QString strPath;
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
