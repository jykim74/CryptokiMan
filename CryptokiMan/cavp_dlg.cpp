#include <QDir>
#include <QTextStream>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QDateTime>
#include <QStringList>

#include "cavp_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "settings_mgr.h"
#include "mech_mgr.h"
#include "cryptoki_api.h"

static const int kACVP_TYPE_BLOCK_CIPHER = 0;
static const int kACVP_TYPE_HASH = 1;
static const int kACVP_TYPE_MAC = 2;
static const int kACVP_TYPE_RSA = 3;
static const int kACVP_TYPE_ECDSA = 4;
static const int kACVP_TYPE_DRBG = 5;
static const int kACVP_TYPE_KDA = 6;
static const int kACVP_TYPE_EDDSA = 7;
static const int kACVP_TYPE_DSA = 8;

static QStringList kACVP_HashList =
    { "SHA-1", "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512" };
static QStringList kACVP_BlockCipherList =
    { "ACVP-AES-ECB", "ACVP-AES-CBC", "ACVP-AES-CFB128", "ACVP-AES-OFB", "ACVP-AES-CTR", "ACVP-AES-CCM", "ACVP-AES-KW", "ACVP-AES-KWP", "ACVP-AES-GCM" };
static QStringList kACVP_MACList =
    { "HMAC-SHA-1", "HMAC-SHA2-224", "HMAC-SHA2-256", "HMAC-SHA2-384", "HMAC-SHA2-512", "ACVP-AES-GMAC", "CMAC-AES" };
static QStringList kACVP_RSAList = { "RSA" };
static QStringList kACVP_ECDSAList = { "ECDSA" };
static QStringList kACVP_DRBGList = { "ctrDRBG", "hashDRBG", "hmacDRBG" };
static QStringList kACVP_KDAList = { "KAS-ECC", "kdf-components", "PBKDF" };
static QStringList kACVP_EDDSAList = { "EDDSA" };
static QStringList kACVP_DSAList = { "DSA" };

const QStringList kSymAlgList = { "AES", "DES3" };
const QStringList kSymModeList = { "ECB", "CBC", "CTR", "CFB", "OFB" };
const QStringList kSymDirection = { "Encrypt", "Decrypt" };
const QStringList kHashAlgList = { "SHA-1", "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512" };
const QStringList kMctVersion = { "Standard", "Alternate" };

const QStringList kSymTypeList = { "KAT", "MCT", "MMT" };

const QStringList kAEModeList = { "GCM", "CCM" };
const QStringList kAETypeList = { "AE", "AD" };

const QStringList kHashTypeList = { "Short", "Long", "Monte" };
const QStringList kECCAlgList = { "ECDSA", "ECDH" };
const QStringList kECCTypeECDSA = { "KPG", "PKV", "SGT", "SVT" };
const QStringList kECCTypeECDH = { "KAKAT", "PKV", "KPG" };

const QStringList kRSAAlgList = { "RSAES", "RSAPSS" };
const QStringList kRSATypeRSAES = { "DET", "ENT", "KGT" };
const QStringList kRSATypeRSAPSS = { "KPG", "SGT", "SVT" };

int getACVPType( const QString strAlg )
{
    for( int i = 0; i < kACVP_HashList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_HashList.at(i).toUpper() )
            return kACVP_TYPE_HASH;
    }

    for( int i = 0; i < kACVP_BlockCipherList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_BlockCipherList.at(i).toUpper() )
            return kACVP_TYPE_BLOCK_CIPHER;
    }

    for( int i = 0; i < kACVP_MACList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_MACList.at(i).toUpper() )
            return kACVP_TYPE_MAC;
    }

    for( int i = 0; i < kACVP_RSAList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_RSAList.at(i).toUpper() )
            return kACVP_TYPE_RSA;
    }

    for( int i = 0; i < kACVP_ECDSAList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_ECDSAList.at(i).toUpper() )
            return kACVP_TYPE_ECDSA;
    }

    for( int i = 0; i < kACVP_DRBGList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_DRBGList.at(i).toUpper() )
            return kACVP_TYPE_DRBG;
    }

    for( int i = 0; i < kACVP_KDAList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_KDAList.at(i).toUpper() )
            return kACVP_TYPE_KDA;
    }

    for( int i = 0; i < kACVP_EDDSAList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_EDDSAList.at(i).toUpper() )
            return kACVP_TYPE_EDDSA;
    }

    for( int i = 0; i < kACVP_DSAList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_DSAList.at(i).toUpper() )
            return kACVP_TYPE_DSA;
    }

    return -1;
}

CAVPDlg::CAVPDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mFindRspBtn, SIGNAL(clicked()), this, SLOT(clickFindRsp()));

    connect( mSymRunBtn, SIGNAL(clicked()), this, SLOT(clickSymRun()));
    connect( mAERunBtn, SIGNAL(clicked()), this, SLOT(clickAERun()));
    connect( mHashRunBtn, SIGNAL(clicked()), this, SLOT(clickHashRun()));
    connect( mMACRunBtn, SIGNAL(clicked()), this, SLOT(clickMACRun()));
    connect( mECCRunBtn, SIGNAL(clicked()), this, SLOT(clickECCRun()));
    connect( mRSARunBtn, SIGNAL(clicked()), this, SLOT(clickRSARun()));

    connect( mSymFindBtn, SIGNAL(clicked()), this, SLOT(clickSymFind()));
    connect( mAEFindBtn, SIGNAL(clicked()), this, SLOT(clickAEFind()));
    connect( mHashFindBtn, SIGNAL(clicked()), this, SLOT(clickHashFind()));
    connect( mMACFindBtn, SIGNAL(clicked()), this, SLOT(clickMACFind()));
    connect( mECCFindBtn, SIGNAL(clicked()), this, SLOT(clickECCFind()));
    connect( mRSAFindBtn, SIGNAL(clicked()), this, SLOT(clickRSAFind()));

    connect( mMCT_SymClearBtn, SIGNAL(clicked()), this, SLOT(clickMCT_SymClear()));
    connect( mMCT_HashClearBtn, SIGNAL(clicked()), this, SLOT(clickMCT_HashClear()));
    connect( mMCT_SymRunBtn, SIGNAL(clicked()), this, SLOT(clickMCT_SymRun()));
    connect( mMCT_HashRunBtn, SIGNAL(clicked()), this, SLOT(clickMCT_HashRun()));
    connect( mACVP_ClearBtn, SIGNAL(clicked()), this, SLOT(clickACVP_Clear()));
    connect( mACVP_RunBtn, SIGNAL(clicked()), this, SLOT(clickACVP_Run()));
    connect( mACVP_LDTClearBtn, SIGNAL(clicked()), this, SLOT(clickACVP_LDTClear()));
    connect( mACVP_LDTRunBtn, SIGNAL(clicked()), this, SLOT(clickACVP_LDTRun()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    initUI();

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CAVPDlg::~CAVPDlg()
{

}

void CAVPDlg::initUI()
{
    mMCT_SymAlgCombo->addItems( kSymAlgList );
    mMCT_SymModeCombo->addItems( kSymModeList );
    mMCT_SymDirectionCombo->addItems( kSymDirection );
    mMCT_HashAlgCombo->addItems( kHashAlgList );
    mMCT_HashMctVersionCombo->addItems( kMctVersion );

    mACVP_LDTHashCombo->addItems( kMechDigestList );



    mSymAlgCombo->addItems( kSymAlgList );
    mSymModeCombo->addItems( kSymModeList );
    mSymTypeCombo->addItems( kSymTypeList );

    mAEAlgCombo->addItems( kSymAlgList );
    mAEModeCombo->addItems( kAEModeList );
    mAETypeCombo->addItems( kAETypeList );

    mHashAlgCombo->addItems( kHashAlgList );
    mHashTypeCombo->addItems( kHashTypeList );

    mMACHashCombo->addItems( kHashAlgList );

    mECCAlgCombo->addItems( kECCAlgList );
    mECCParamCombo->addItems( kECCOptionList );
    mECCHashCombo->addItems( kHashAlgList );
    mECCTypeCombo->addItems( kECCTypeECDSA );

    mRSAAlgCombo->addItems( kRSAAlgList );
    mRSAHashCombo->addItems( kHashAlgList );
    mRSA_EText->setText( "65537" );
    mRSATypeCombo->addItems( kRSATypeRSAES );

    mTabWidget->setCurrentIndex(0);
}

void CAVPDlg::initialize()
{

}

void CAVPDlg::setSelectedSlot(int index)
{
    slotChanged( index );
}

void CAVPDlg::slotChanged(int index)
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

void CAVPDlg::clickFindRsp()
{
    QString strRspPath = mRspPathText->text();
    if( strRspPath.length() < 1 ) strRspPath = manApplet->curPath();

    QString strFileName = findFile( this, JS_FILE_TYPE_TXT, strRspPath );
    if( strFileName.length() > 0 )
    {
        mRspPathText->setText( strFileName );
    }
}

void CAVPDlg::clickSymRun()
{
    int ret = 0;
    manApplet->log( "SymRun\n" );

    if( mSymReqPathText->text().length() < 1 )
    {
        manApplet->warningBox( tr("Select requested file"), this );
        mSymReqPathText->setFocus();
        return;
    }

    QString strPath = mSymReqPathText->text();
    QFile reqFile( strPath );
    QString strAlg = mSymAlgCombo->currentText();


    QString strRspName = getRspFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        manApplet->elog( QString( "failed to open file(%1)\n").arg( strPath ));
        return;
    }

    QTextStream in( &reqFile );
    QString strLine = in.readLine();
    int nPos = 0;
    int nLen = 0;
    QString strKey;
    QString strIV;
    QString strPT;
    QString strType = mSymTypeCombo->currentText();
    QString strMode = mSymModeCombo->currentText();

    logRsp( QString( "# SYM-%1-%2-%3 Response")
               .arg( mSymAlgCombo->currentText())
               .arg( mSymModeCombo->currentText())
               .arg( mSymTypeCombo->currentText()) );

    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();

        if( nLen > 0 )
        {
            getNameValue( strLine, strName, strValue );

            if( strName == "KEY" )
                strKey = strValue;
            else if( strName == "IV" )
                strIV = strValue;
            else if( strName == "PT" )
                strPT = strValue;
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( strKey.length() > 0 )
            {
                if( strKey.length() > 0 ) logRsp( QString( "Key = %1").arg( strKey ));
                if( strIV.length() > 0 ) logRsp( QString( "IV = %1").arg( strIV ));
                if( strPT.length() > 0 ) logRsp( QString( "PT = %1").arg( strPT ));
#if 0
                if( strType == "MCT" )
                {
                    if( strMode == "CBC" )
                    {
                        ret = makeSymCBC_MCT( strAlg, strKey, strIV, strPT, NULL);
                    }
                    else if( strMode == "ECB" )
                    {
                        ret = makeSymECB_MCT( strAlg, strKey, strPT, NULL );
                    }
                    else if( strMode == "CTR" )
                    {
                        ret = makeSymCTR_MCT( strAlg, strKey, strIV, strPT, NULL );
                    }
                    else if( strMode == "CFB" )
                    {
                        ret = makeSymCFB_MCT( strAlg, strKey, strIV, strPT, NULL );
                    }
                    else if( strMode == "OFB" )
                    {
                        ret = makeSymOFB_MCT( strAlg, strKey, strIV, strPT, NULL );
                    }
                }
                else
                    ret = makeSymData( strKey, strIV, strPT );
#endif

                if( ret != 0 )
                {
                    manApplet->warningBox( tr( "SYM execution failed [%1]").arg(ret), this);
                    return;
                }
            }

            strKey.clear();
            strIV.clear();
            strPT.clear();
        }

        strLine = strNext;
        nPos++;
    }

    manApplet->messageBox( tr("CAVP completed[Rsp: %1]").arg(strRspName), this );
}

void CAVPDlg::clickAERun()
{

}

void CAVPDlg::clickHashRun()
{
    int ret = 0;
    manApplet->log( "Hash execution" );

    if( mHashReqPathText->text().length() < 1 )
    {
        manApplet->warningBox( tr("Select requested file"), this );
        mHashReqPathText->setFocus();
        return;
    }

    QString strPath = mHashReqPathText->text();
    QFile reqFile( strPath );
    QString strAlg = mHashAlgCombo->currentText();

    QString strRspName = getRspFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        manApplet->elog( QString( "fail to open file(%1)\n").arg( strPath ));
        return;
    }

    QTextStream in( &reqFile );
    QString strLine = in.readLine();

    QString strL;
    QString strLen;
    QString strMsg;
    QString strSeed;

    int nPos = 0;
    int nLen = 0;

    logRsp( QString( "# HASH-%1-%2 Response")
               .arg( mHashAlgCombo->currentText())
               .arg( mHashTypeCombo->currentText()) );

    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();
        //        manApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

        if( nLen > 0 )
        {
            getNameValue( strLine, strName, strValue );
            manApplet->log( QString( "Name:%1 Value:%2").arg(strName).arg(strValue));

            if( strName == "L" )
                strL = strValue;
            else if( strName == "Len" )
                strLen = strValue;
            else if( strName == "Msg" )
                strMsg = strValue;
            else if( strName == "Seed" )
                strSeed = strValue;
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( strL.length() > 0 )
            {
                logRsp( QString( "L = %1").arg( strL ));
                logRsp( "" );
                strL.clear();
            }

            if( strMsg.length() > 0 && strLen.length() > 0 )
            {
//                ret = makeHashData( strLen.toInt(), strMsg );
            }
            else if( strSeed.length() > 0 )
            {
 //               ret = makeHashMCT( mHashAlgCombo->currentText(), strSeed, NULL );
            }

            strMsg.clear();
            strLen.clear();
            strSeed.clear();

            if( ret != 0 )
            {
                manApplet->warningBox( tr( "Hash execution failed [%1]" ).arg(ret), this);
                return;
            }
        }

        strLine = strNext;
        nPos++;
    }

    manApplet->messageBox( tr("CAVP completed[Rsp: %1]").arg(strRspName), this );
}

void CAVPDlg::clickMACRun()
{
    int ret = 0;
    manApplet->log( "Hash execution" );

    if( mMACReqPathText->text().length() < 1 )
    {
        manApplet->warningBox( tr("Select requested file"), this );
        mMACReqPathText->setFocus();
        return;
    }

    QString strPath = mMACReqPathText->text();
    QFile reqFile( strPath );

    QString strRspName = getRspFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        manApplet->elog( QString( "failed to open file(%1)\n").arg( strPath ));
        return;
    }

    QTextStream in( &reqFile );
    QString strLine = in.readLine();

    QString strL;
    QString strCount;
    QString strKLen;
    QString strTLen;
    QString strKey;
    QString strMsg;

    int nPos = 0;
    int nLen = 0;

    logRsp( QString( "# MAC-%1 Response")
               .arg( mMACHashCombo->currentText()) );

    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();
        //        manApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

        if( nLen > 0 )
        {
            getNameValue( strLine, strName, strValue );
            //            manApplet->log( QString( "Name:%1 Value:%2").arg(strName).arg(strValue));

            if( strName == "COUNT" )
                strCount = strValue;
            else if( strName == "Klen" )
                strKLen = strValue;
            else if( strName == "Tlen" )
                strTLen = strValue;
            else if( strName == "Key" )
                strKey = strValue;
            else if( strName == "Msg" )
                strMsg = strValue;
            else if( strName == "L" )
                strL = strValue;
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( strL.length() > 0 )
            {
                logRsp( QString( "L = %1").arg(strL));
                logRsp( "" );

                strL.clear();
            }

            if( strCount.length() > 0 && strKLen.length() > 0 && strTLen.length() > 0 && strKey.length() > 0 && strMsg.length() > 0 )
            {
 //               ret = makeHMACData( strCount, strKLen, strTLen, strKey, strMsg );

                if( ret != 0 )
                {
                    manApplet->warningBox( tr( "HMAC execution failed [%1]").arg(ret), this);
                    return;
                }
            }

            strCount.clear();
            strKLen.clear();
            strTLen.clear();
            strKey.clear();
            strMsg.clear();
        }

        strLine = strNext;
        nPos++;
    }

    manApplet->messageBox( tr("CAVP completed[Rsp: %1]").arg(strRspName), this );
}

void CAVPDlg::clickECCRun()
{
    manApplet->log( "ECC execution" );
    int ret = 0;
    bool bInit = true;

    if( mECCReqPathText->text().length() < 1 )
    {
        manApplet->warningBox( tr("Select requested file"), this );
        mECCReqPathText->setFocus();
        return;
    }

    QString strPath = mECCReqPathText->text();
    QFile reqFile( strPath );

    QString strRspName = getRspFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        manApplet->elog( QString( "failed to open file(%1)").arg(strPath));
        return;
    }

    int nPos = 0;
    int nLen = 0;

    QString strYX;
    QString strYY;
    QString strM;
    QString strR;
    QString strS;

    QString strQX;
    QString strQY;
    QString strRA;
    QString strRB;
    QString strKTA1X;
    QString strKTA1Y;

    QTextStream in( &reqFile );
    QString strLine = in.readLine();
    QString strParam = mECCParamCombo->currentText();
    QString strHash = mECCHashCombo->currentText();
#if 0
    logRsp( QString( "# ECC-%1-%2-%3 Response")
               .arg( mECC_ECDSARadio->isChecked() ? "ECDSA" : "ECDH" )
               .arg( mECCParamCombo->currentText() )
               .arg( mECCTypeCombo->currentText()));

    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();
        //       manApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

        if( nLen > 0 )
        {
            strLine.remove( '[' );
            strLine.remove( ']' );

            getNameValue( strLine, strName, strValue );

            if( strName == "Yx" )
                strYX = strValue;
            else if( strName == "Yy" )
                strYY = strValue;
            else if( strName == "M" )
                strM = strValue;
            else if( strName == "R" )
                strR = strValue;
            else if( strName == "S" )
                strS = strValue;
            else if( strName == "Qx" )
                strQX = strValue;
            else if( strName == "Qy" )
                strQY = strValue;
            else if( strName == "rA" )
                strRA = strValue;
            else if( strName == "rB" )
                strRB = strValue;
            else if( strName == "KTA1x" )
                strKTA1X = strValue;
            else if( strName == "KTA1y" )
                strKTA1Y = strValue;
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( mECC_ECDSARadio->isChecked() && mECCTypeCombo->currentText() == "KPG" )
            {
                if( bInit == true )
                {
                    logRsp( QString("[%1]").arg( strParam) );
                    logRsp( "" );
                    bInit = false;
                }

                ret = makeECDSA_KPG( strParam, 10 );
                if( ret != 0 )
                {
                    manApplet->warningBox( tr( "ECC execution fail [%1]").arg(ret), this );
                    return;
                }
            }
            else if( mECC_ECDSARadio->isChecked() && mECCTypeCombo->currentText() == "PKV" )
            {
                if( bInit == true )
                {
                    logRsp( QString("[%1]").arg( strParam) );
                    logRsp( "" );
                    bInit = false;
                }

                if( strYX.length() > 0 && strYY.length() > 0 )
                {
                    ret = makeECDSA_PKV( strParam, strYX, strYY );
                    if( ret != 0 )
                    {
                        manApplet->warningBox( tr( "ECC execution fail [%1]").arg(ret), this);
                        return;
                    }
                }
            }
            else if( mECC_ECDSARadio->isChecked() && mECCTypeCombo->currentText() == "SGT" )
            {
                if( bInit == true )
                {
                    logRsp( QString("[%1, %2]").arg( strParam ).arg( strHash ) );
                    logRsp( "" );
                    bInit = false;
                }

                if( strM.length() > 0 )
                {
                    ret = makeECDSA_SGT( strParam, strHash, strM );
                    if( ret != 0 )
                    {
                        manApplet->warningBox( tr( "ECC execution fail [%1]").arg(ret), this);
                        return;
                    }
                }
            }
            else if( mECC_ECDSARadio->isChecked() && mECCTypeCombo->currentText() == "SVT" )
            {
                if( bInit == true )
                {
                    logRsp( QString("[%1, %2]").arg( strParam ).arg( strHash ) );
                    logRsp( "" );
                    bInit = false;
                }

                if( strM.length() > 0 && strYX.length() > 0 && strYY.length() > 0 && strR.length() > 0 && strS.length() > 0 )
                {
                    ret = makeECDSA_SVT( strParam, strHash, strM, strYX, strYY, strR, strS );
                    if( ret != 0 )
                    {
                        manApplet->warningBox( tr( "ECC execution fail [%1]").arg(ret), this );
                        return;
                    }
                }
            }
            else if( mECC_ECDHRadio->isChecked() && mECCTypeCombo->currentText() == "KPG" )
            {
                if( bInit )
                {
                    logRsp( QString("[%1]").arg( strParam) );
                    logRsp( "" );
                    bInit = false;
                }

                ret = makeECDH_KPG( strParam, 15 );
                if( ret != 0 )
                {
                    manApplet->warningBox( tr( "ECC execution fail [%1]").arg(ret), this );
                    return;
                }
            }
            else if( mECC_ECDHRadio->isChecked() && mECCTypeCombo->currentText() == "PKV" )
            {
                if( bInit )
                {
                    logRsp( QString("[%1]").arg( strParam) );
                    logRsp( "" );
                    bInit = false;
                }

                if( strQX.length() > 0 && strQY.length() > 0 )
                {
                    ret = makeECDH_PKV( strParam, strQX, strQY );

                    if( ret != 0 )
                    {
                        manApplet->warningBox( tr( "ECC execution fail [%1]").arg(ret), this );
                        return;
                    }
                }
            }
            else if( mECC_ECDHRadio->isChecked() && mECCTypeCombo->currentText() == "KAKAT" )
            {
                if( bInit )
                {
                    logRsp( QString("[%1]").arg( strParam) );
                    logRsp( "" );
                    bInit = false;
                }

                if( strRA.length() > 0 && strRB.length() > 0 && strKTA1X.length() > 0 && strKTA1Y.length() > 0 )
                {
                    ret = makeECDH_KAKAT( strParam, strRA, strRB, strKTA1X, strKTA1Y );

                    if( ret != 0 )
                    {
                        manApplet->warningBox( tr( "ECC execution fail [%1]").arg(ret), this );
                        return;
                    }
                }
            }

            strM.clear();
            strYX.clear();
            strYY.clear();
            strR.clear();
            strS.clear();

            strQX.clear();
            strQY.clear();
            strRA.clear();
            strRB.clear();
            strKTA1X.clear();
            strKTA1Y.clear();
        }

        strLine = strNext;
        nPos++;
    }
#endif

    manApplet->messageBox( tr("CAVP completed[Rsp: %1]").arg(strRspName), this );
}

void CAVPDlg::clickRSARun()
{
    int ret = 0;
    bool bInit = true;
    manApplet->log( "RSA execution" );

    if( mRSAReqPathText->text().length() < 1 )
    {
        manApplet->warningBox( tr( "Select requested file" ), this );
        mRSAReqPathText->setFocus();
        return;
    }

    QString strPath = mRSAReqPathText->text();
    QFile reqFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        manApplet->elog( QString( "failed to open file(%1)").arg(strPath));
        return;
    }

    QString strRspName = getRspFile( strPath );

    int nPos = 0;
    int nLen = 0;

    int nKeyLen = -1;

    QString strM;
    QString strS;
    QString strN;
    QString strC;

    QTextStream in( &reqFile );
    QString strLine = in.readLine();
    QString strHash = mRSAHashCombo->currentText();
    int nE = mRSA_EText->text().toInt();

    BIN binPri = {0,0};
    BIN binPub = {0,0};

#if 0
    logRsp( QString( "# RSA-%1-%2 Response")
               .arg( mRSA_ESRadio->isChecked() ? "RSA_ES" : "RSA_PSS" )
               .arg( mRSATypeCombo->currentText() ));

    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();
        //       manApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

        if( nLen > 0 )
        {
            getNameValue( strLine, strName, strValue );

            if( strName == "|n|" || strName == "mod" )
                nKeyLen = strValue.toInt();
            else if( strName == "n" )
                strN = strValue;
            else if( strName == "M" )
                strM = strValue;
            else if( strName == "S" )
                strS = strValue;
            else if( strName == "C" )
                strC = strValue;
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( mRSA_PSSRadio->isChecked() && mRSATypeCombo->currentText() == "KPG" )
            {
                if( nKeyLen > 0 )
                {
                    if( bInit == true )
                    {
                        logRsp( QString( "|n| = %1").arg(nKeyLen));
                        logRsp( "" );
                        bInit = false;
                    }

                    ret = makeRSA_PSS_KPG( nKeyLen, nE, 10 );
                    nKeyLen = -1;
                    if( ret != 0 )
                    {
                        manApplet->warningBox( tr( "RSA execution failed [%1]").arg(ret), this );
                        return;
                    }
                }
            }
            else if( mRSA_PSSRadio->isChecked() && mRSATypeCombo->currentText() == "SGT" )
            {
                if( nKeyLen > 0 && nE > 0 && bInit == true)
                {
                    JRSAKeyVal sRSAKeyVal;

                    memset( &sRSAKeyVal, 0x00, sizeof(sRSAKeyVal ));


                    ret = JS_PKI_RSAGenKeyPair( nKeyLen, nE, &binPub, &binPri );
                    if( ret != 0 ) return;

                    JS_PKI_getRSAKeyVal( &binPri, &sRSAKeyVal );
                    strN = sRSAKeyVal.pN;

                    logRsp( QString( "mod = %1").arg( nKeyLen ));
                    logRsp( QString( "HashAlg = %1").arg( strHash ));
                    logRsp( "" );
                    logRsp( QString( "n = %1" ).arg( strN ));
                    logRsp( QString( "e = %1").arg(nE));

                    logRsp( "" );

                    bInit = false;
                    JS_PKI_resetRSAKeyVal( &sRSAKeyVal );
                }

                if( strM.length() > 0 && nE > 0 && binPri.nLen > 0 )
                {
                    ret = makeRSA_PSS_SGT( nE, getHexString(&binPri), strHash, strM );
                    if( ret != 0 )
                    {
                        manApplet->warningBox( tr( "RSA execution failed [%1]").arg(ret), this );
                        JS_BIN_reset( &binPri );
                        JS_BIN_reset( &binPub );
                        return;
                    }
                }
            }
            else if( mRSA_PSSRadio->isChecked() && mRSATypeCombo->currentText() == "SVT" )
            {
                if( strN.length() > 0 && nE > 0 && bInit == true)
                {
                    logRsp( QString( "mod = %1").arg( nKeyLen ));
                    logRsp( QString( "HashAlg = %1").arg( strHash ));
                    logRsp( "" );
                    logRsp( QString( "n = %1").arg( strN));
                    logRsp( QString( "e = %1").arg(nE));
                    logRsp( "" );

                    bInit = false;
                }

                if( strS.length() > 0 && strM.length() > 0 )
                {
                    ret = makeRSA_PSS_SVT( nE, strN, strHash, strM, strS );
                    if( ret != 0 )
                    {
                        manApplet->warningBox( tr( "RSA execution failed [%1]").arg(ret), this );
                        return;
                    }
                }
            }
            else if( mRSA_ESRadio->isChecked() && mRSATypeCombo->currentText() == "DET" )
            {
                if( bInit == true )
                {
                    QString strPriPath = mRSA_DETPriPathText->text();
                    if( strPriPath.length() < 1 )
                    {
                        manApplet->warningBox( tr( "Select RSA private key for DET" ), this );
                        return;
                    }

                    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );

                    logRsp( QString( "|n| = %1").arg(nKeyLen));
                    logRsp( QString( "n = %1").arg( strN ));
                    logRsp( QString( "e = %1").arg( nE ) );
                    logRsp( "" );
                    bInit = false;
                }

                if( strC.length() > 0 && binPri.nLen > 0 )
                {
                    logRsp( QString( "SHAAlg = %1").arg(strHash));

                    ret = makeRSA_ES_DET( getHexString( &binPri ), strC );

                    if( ret != 0 )
                    {
                        JS_BIN_reset( &binPri );
                        return;
                    }
                }
            }
            else if( mRSA_ESRadio->isChecked() && mRSATypeCombo->currentText() == "ENT" )
            {
                if( strN.length() > 0 && nE > 0 && bInit == true)
                {
                    logRsp( QString("|n| = %1").arg( strN.length()/2 ));
                    logRsp( QString( "n = %1").arg( strN));
                    logRsp( QString( "e = %1").arg(nE));
                    logRsp( "" );

                    bInit = false;
                }

                if( strM.length() > 0 && strN.length() > 0 )
                {
                    ret = makeRSA_ES_ENT( nE, strN, strM );

                    if( ret != 0 ) return;
                }
            }
            else if( mRSA_ESRadio->isChecked() && mRSATypeCombo->currentText() == "KGT" )
            {
                if( nKeyLen > 0 && nE > 0 )
                {
                    if( bInit == true )
                    {
                        logRsp( QString( "|n| = %1").arg(nKeyLen));
                        logRsp( QString( "e = %1").arg(nE));
                        logRsp( "" );
                        bInit = false;
                    }

                    ret = makeRSA_ES_KGT( nKeyLen, nE, 10 );
                    nKeyLen = -1;
                    if( ret != 0 ) return;
                }
            }

            strS.clear();
            strM.clear();
            //            strN.clear();
            strC.clear();

            if( mRSA_ESRadio->isChecked() ) strHash.clear();
        }


        strLine = strNext;
        nPos++;
    }

    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
#endif

    manApplet->messageBox( tr("CAVP completed[Rsp: %1]").arg(strRspName), this );
}

void CAVPDlg::clickSymFind()
{

}

void CAVPDlg::clickAEFind()
{

}

void CAVPDlg::clickHashFind()
{

}

void CAVPDlg::clickMACFind()
{

}

void CAVPDlg::clickECCFind()
{

}

void CAVPDlg::clickRSAFind()
{

}

void CAVPDlg::clickMCT_SymClear()
{

}

void CAVPDlg::clickMCT_HashClear()
{

}

void CAVPDlg::clickMCT_SymRun()
{
    int ret = 0;
    QJsonArray jArr;

    BIN binKey = {0,0};
    BIN binIV = {0,0};
    BIN binPT = {0,0};
    BIN binCT = {0,0};

    QString strAlg = mMCT_SymAlgCombo->currentText();
    QString strMode = mMCT_SymModeCombo->currentText();
    QString strDirection = mMCT_SymDirectionCombo->currentText();

    QString strKey = mMCT_SymKeyText->text();
    QString strIV = mMCT_SymIVText->text();
    QString strPT = mMCT_SymPTText->text();
    QString strCT = mMCT_SymCTText->text();

    QString strAlgMode = QString( "%1-%2").arg( strAlg ).arg( strMode );

    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
    JS_BIN_decodeHex( strPT.toStdString().c_str(), &binPT );
    JS_BIN_decodeHex( strCT.toStdString().c_str(), &binCT );

    if( strDirection.toLower() == "encrypt" )
        ret = makeSym_MCT( strAlgMode, &binKey, &binIV, &binPT, jArr, true );
    else
        ret = makeSymDec_MCT( strAlgMode, &binKey, &binIV, &binCT, jArr, true );

    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binPT );
    JS_BIN_reset( &binCT );
}

void CAVPDlg::clickMCT_HashRun()
{
    int ret = 0;
    BIN binSeed = {0,0};
    QJsonArray jArr;

    QString strAlg = mMCT_HashAlgCombo->currentText();
    QString strMctVersion = mMCT_HashMctVersionCombo->currentText();
    QString strSeed = mMCT_HashSeedText->text();

    JS_BIN_decodeHex( strSeed.toStdString().c_str(), &binSeed );

    if( strMctVersion.toLower() == "alternate" )
        ret = makeHash_AlternateMCT( strAlg, &binSeed, jArr, true );
    else
        ret = makeHash_MCT( strAlg, &binSeed, jArr, true );

    JS_BIN_reset( &binSeed );
}

void CAVPDlg::clickACVP_Clear()
{

}

void CAVPDlg::clickACVP_Run()
{
    int ret = 0;

    QString strReqPath = mACVP_ReqPathText->text();
    QJsonDocument jReqDoc;

    QJsonDocument jRspDoc;
    QJsonArray jRspArr;
    QJsonObject jRspObj;
    QJsonArray jRspTestGroupArr;

    if( mACVP_SetTGIDCheck->isChecked() == true )
    {
        if( mACVP_SetTGIDText->text().length() < 1 )
        {
            manApplet->warningBox( tr( "Enter a tgId" ), this );
            mACVP_SetTGIDText->setFocus();
            return;
        }
    }

    if( mACVP_SetTCIDCheck->isChecked() == true )
    {
        if( mACVP_SetTCIDText->text().length() < 1 )
        {
            manApplet->warningBox( tr( "Enter a tcId" ), this );
            mACVP_SetTCIDText->setFocus();
            return;
        }
    }

    ret = readJsonReq( strReqPath, jReqDoc );
    if( ret != 0 ) return;

    QJsonArray jArr = jReqDoc.array();

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();


        if( i == 0 )
        {
            jRspArr.insert( 0, jObj );
        }
        else if( i == 1 )
        {
            QString strAlg = jObj["algorithm"].toString();
            QString strRevision = jObj["revision"].toString();
            QString strMode = jObj["mode"].toString();
            int nVsId = jObj["vsId"].toInt();

            QJsonArray jTestGroupArr = jObj["testGroups"].toArray();

            //            if( strAlg == "ECDSA" || strAlg == "RSA" ) strAlg = strMode;

            jRspObj["algorithm"] = strAlg;
            jRspObj["revision"] = strRevision;
            jRspObj["vsId"] = nVsId;
            if( strMode.length() > 0 ) jRspObj["mode"] = strMode;

            for( int k = 0; k < jTestGroupArr.size(); k++ )
            {
                QJsonValue jSubVal = jTestGroupArr.at(k);
                QJsonObject jSubObj = jSubVal.toObject();
                int nTgId = jSubObj["tgId"].toInt();
                QJsonObject jRspObject;

                if( mACVP_SetTGIDCheck->isChecked() == true )
                {
                    int nSetTgId = mACVP_SetTGIDText->text().toInt();
                    if( nSetTgId != nTgId ) continue;
                }

                ret = makeUnitJsonWork( strAlg, strMode, jSubObj, jRspObject );
                if( ret != 0 ) break;

                if( mACVP_SetTGIDCheck->isChecked() == true )
                    jRspTestGroupArr.insert( 0, jRspObject );
                else
                    jRspTestGroupArr.insert( k, jRspObject );
            }

            jRspObj["testGroups"] = jRspTestGroupArr;
            jRspArr.insert( 1, jRspObj );
        }
    }

    jRspDoc.setArray( jRspArr );
    saveJsonRsp( jRspDoc );
}

void CAVPDlg::clickACVP_LDTClear()
{

}

void CAVPDlg::clickACVP_LDTRun()
{
    int ret = 0;

    int nMech = -1;
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sDigest[128];
    long uDigestLen = 0;

    CK_MECHANISM sMech;
    QString strHash = mACVP_LDTHashCombo->currentText();
    QString strFullLength = mACVP_LDTFullLengthBitsText->text();

    if( strFullLength.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a full length" ), this );
        mACVP_LDTFullLengthBitsText->setFocus();
        return;
    }

    QString strContent = mACVP_LDTContentText->text();
    if( strContent.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a content" ), this );
        mACVP_LDTContentText->setFocus();
        return;
    }

    nMech = JS_PKCS11_GetCKMType( strHash.toStdString().c_str() );
    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = nMech;

    mACVP_LDTProgressBar->setValue( 0 );
    mACVP_LDTStatusText->clear();

    BIN binContent = {0,0};

    qint64 nFullLength = strFullLength.toLongLong() / 8;
    qint64 nCurLength = 0;

    JS_BIN_decodeHex( strContent.toStdString().c_str(), &binContent );

    ret = pAPI->DigestInit( hSession, &sMech );
    if( ret != 0 ) goto end;

    while( nFullLength > nCurLength )
    {
        int nPercent = 0;

        ret = pAPI->DigestUpdate( hSession, binContent.pVal, binContent.nLen, false );
        if( ret != 0 ) goto end;

        nCurLength += binContent.nLen;

        nPercent = ( nCurLength * 100 ) / nFullLength;

        manApplet->log( QString( "CurLength: %1" ).arg( nCurLength * 8));
        mACVP_LDTProgressBar->setValue( nPercent );
        mACVP_LDTStatusText->setText( QString( "%1").arg( nCurLength * 8));
    }

    uDigestLen = sizeof(sDigest);
    ret = pAPI->DigestFinal( hSession, sDigest, (CK_ULONG_PTR)&uDigestLen );
    if( ret == 0 )
    {
        mACVP_LDT_MDText->setText( getHexString( sDigest, uDigestLen ));
    }

end :
    JS_BIN_reset( &binContent );
}

void CAVPDlg::logRsp( QString strLog )
{
    manApplet->log( strLog );

    QString strRspPath = mRspPathText->text();
    if( strRspPath.length() < 2 ) return;

    QFile file( strRspPath );
    file.open(QFile::WriteOnly | QFile::Append| QFile::Text );
    QTextStream SaveFile( &file );
    SaveFile << strLog << "\n";
    file.close();
}

QString CAVPDlg::getRspFile(const QString &reqFileName )
{
    QFileInfo fileInfo;
    fileInfo.setFile( reqFileName );

    QString strRspPath = mRspPathText->text();


    QString fileName = fileInfo.baseName();
    QString extName = fileInfo.completeSuffix();
    QString filePath = fileInfo.canonicalPath();

    QString fileRspName = QString( "%1.rsp" ).arg( fileName );
    QString strPath = QString( "%1/%2").arg( strRspPath ).arg( fileRspName );

    manApplet->log( QString( "RspName: %1").arg(strPath));

    return strPath;
}

int CAVPDlg::getNameValue( const QString strLine, QString& name, QString& value )
{
    if( strLine.isEmpty() ) return -1;

    QStringList nameVal = strLine.split( "=" );

    if( nameVal.size() >= 1 )
        name = nameVal.at(0).trimmed();

    if( nameVal.size() >= 2 )
        value = nameVal.at(1).trimmed();

    return 0;
}

int CAVPDlg::createKey( int nKeyType, const BIN *pKey, long *phObj )
{
    int ret = 0;
    bool bToken = false;
    long hSession = mSessionText->text().toLong();
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();

    static unsigned char s_sTestID[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };


    CK_ATTRIBUTE sTemplate[10];
    int nCount = 0;

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;

    memset( sTemplate, 0x00, sizeof(sTemplate));

    char sLabel[128] = "CreateKey";

    memset( sTemplate, 0x00, sizeof(sTemplate));
    memset( sLabel, 0x00, sizeof(sLabel));

    sTemplate[nCount].type = CKA_CLASS;
    sTemplate[nCount].pValue = &keyClass;
    sTemplate[nCount].ulValueLen = sizeof(keyClass);
    nCount++;

    sTemplate[nCount].type = CKA_KEY_TYPE;
    sTemplate[nCount].pValue = &nKeyType;
    sTemplate[nCount].ulValueLen = sizeof(nKeyType);
    nCount++;

    if( bToken == true )
    {
        sTemplate[nCount].type = CKA_TOKEN;
        sTemplate[nCount].pValue = &kTrue;;
        sTemplate[nCount].ulValueLen = sizeof(CK_BBOOL);
        nCount++;
    }

    sTemplate[nCount].type = CKA_ID;
    sTemplate[nCount].pValue = s_sTestID;
    sTemplate[nCount].ulValueLen = sizeof(s_sTestID);
    nCount++;

    sTemplate[nCount].type = CKA_LABEL;
    sTemplate[nCount].pValue = sLabel;
    sTemplate[nCount].ulValueLen = strlen( sLabel );
    nCount++;

    sTemplate[nCount].type = CKA_VALUE;
    sTemplate[nCount].pValue = pKey->pVal;
    sTemplate[nCount].ulValueLen = pKey->nLen;
    nCount++;

    sTemplate[nCount].type = CKA_WRAP;
    sTemplate[nCount].pValue = &kTrue;
    sTemplate[nCount].ulValueLen = sizeof(CK_BBOOL);
    nCount++;

    sTemplate[nCount].type = CKA_EXTRACTABLE;
    sTemplate[nCount].pValue = &kTrue;
    sTemplate[nCount].ulValueLen = sizeof(CK_BBOOL);
    nCount++;

    sTemplate[nCount].type = CKA_SIGN;
    sTemplate[nCount].pValue = &kTrue;
    sTemplate[nCount].ulValueLen = sizeof(CK_BBOOL);
    nCount++;

    ret = pAPI->CreateObject( hSession, sTemplate, nCount, (CK_OBJECT_HANDLE_PTR)phObj );


    return ret;
}

int CAVPDlg::genKeyPair( int nGenKeyType, long *phPri, long *phPub )
{
    int ret = 0;
    bool bToken = false;
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();

    CK_ATTRIBUTE sPriTemplate[10];
    int nPriCount = 0;

    CK_ATTRIBUTE sPubTemplate[10];
    int nPubCount = 0;

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS priClass = CKO_PRIVATE_KEY;

    long hSession = -1;

    CK_OBJECT_HANDLE hPubKey = -1;
    CK_OBJECT_HANDLE hPriKey = -1;

    char sPubLabel[128] = "GenECCPubKey";
    char sPriLabel[128] = "GenECCPriKey";

    CK_MECHANISM sMech;

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = nGenKeyType;

    hSession = mSessionText->text().toLong();

    /* Pub Template */
    sPubTemplate[nPubCount].type = CKA_CLASS;
    sPubTemplate[nPubCount].pValue = &pubClass;
    sPubTemplate[nPubCount].ulValueLen = sizeof(pubClass);
    nPubCount++;

    if( bToken == true )
    {
        sPubTemplate[nPubCount].type = CKA_TOKEN;
        sPubTemplate[nPubCount].pValue = &kTrue;;
        sPubTemplate[nPubCount].ulValueLen = sizeof(CK_BBOOL);
        nPubCount++;
    }

    /*
    sPubTemplate[nPubCount].type = CKA_ID;
    sPubTemplate[nPubCount].pValue = s_sTestID;
    sPubTemplate[nPubCount].ulValueLen = sizeof(s_sTestID);
    nPubCount++;
    */

    sPubTemplate[nPubCount].type = CKA_LABEL;
    sPubTemplate[nPubCount].pValue = sPubLabel;
    sPubTemplate[nPubCount].ulValueLen = strlen( sPubLabel );
    nPubCount++;

    /* Pri Template */
    sPriTemplate[nPriCount].type = CKA_CLASS;
    sPriTemplate[nPriCount].pValue = &priClass;
    sPriTemplate[nPriCount].ulValueLen = sizeof(priClass);
    nPriCount++;

    if( bToken == true )
    {
        sPriTemplate[nPriCount].type = CKA_TOKEN;
        sPriTemplate[nPriCount].pValue = &kTrue;;
        sPriTemplate[nPriCount].ulValueLen = sizeof(CK_BBOOL);
        nPriCount++;
    }

    sPriTemplate[nPriCount].type = CKA_EXTRACTABLE;
    sPriTemplate[nPriCount].pValue = &kTrue;;
    sPriTemplate[nPriCount].ulValueLen = sizeof(CK_BBOOL);
    nPriCount++;

    sPriTemplate[nPriCount].type = CKA_DERIVE;
    sPriTemplate[nPriCount].pValue = &kTrue;;
    sPriTemplate[nPriCount].ulValueLen = sizeof(CK_BBOOL);
    nPriCount++;

    /*
    sPriTemplate[nPriCount].type = CKA_ID;
    sPriTemplate[nPriCount].pValue = s_sTestID;
    sPriTemplate[nPriCount].ulValueLen = sizeof(s_sTestID);
    nPriCount++;
    */

    sPriTemplate[nPriCount].type = CKA_LABEL;
    sPriTemplate[nPriCount].pValue = sPriLabel;
    sPriTemplate[nPriCount].ulValueLen = strlen( sPriLabel );
    nPriCount++;

    ret = pAPI->GenerateKeyPair( hSession, &sMech, sPubTemplate, nPubCount, sPriTemplate, nPriCount, &hPubKey, &hPriKey );

    if( ret == 0 )
    {
        *phPub = hPubKey;
        *phPri = hPriKey;
    }

    return ret;
}

int _getCKK( const QString strAlg )
{
    if( strAlg == "AES" )
    {
        return CKK_AES;
    }
    else if( strAlg == "DES3" || strAlg == "3DES" )
    {
        return CKK_DES3;
    }

    return -1;
}

int CAVPDlg::makeSym_MCT( const QString strAlgMode, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin )
{
    int ret = 0;
    int nKeyAlg = 0;
    QString strAlg;
    QString strMode;

    QStringList list = strAlgMode.split( "-" );
    if( list.size() < 2 ) return -1;

    strAlg = list.at(0);
    strMode = list.at(1);

    nKeyAlg = _getCKK( strAlg );

    if( strMode == "ECB" )
    {
        ret = makeSymECB_MCT( nKeyAlg, pKey, pPT, jsonRes, bWin );
    }
    else if( strMode == "CBC" )
    {
        ret = makeSymCBC_MCT( nKeyAlg, pKey, pIV, pPT, jsonRes, bWin );
    }
    else if( strMode == "CTR" )
    {
        ret = makeSymCTR_MCT( nKeyAlg, pKey, pIV, pPT, jsonRes, bWin );
    }
    else if( strMode == "OFB" )
    {
        ret = makeSymOFB_MCT( nKeyAlg, pKey, pIV, pPT, jsonRes, bWin );
    }
    else if( strMode == "CFB" || strMode == "CFB128" )
    {
        ret = makeSymCFB_MCT( nKeyAlg, pKey, pIV, pPT, jsonRes, bWin );
    }
    else
    {
        ret = -1;
    }

    return ret;
}

int CAVPDlg::makeSymDec_MCT( const QString strAlgMode, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin )
{
    int ret = 0;
    int nKeyAlg = 0;
    QString strAlg;
    QString strMode;

    QStringList list = strAlgMode.split( "-" );
    if( list.size() < 2 ) return -1;

    strAlg = list.at(0);
    strMode = list.at(1);

    nKeyAlg = _getCKK( strAlg );

    if( strAlgMode == "ECB" )
    {
        ret = makeSymDecECB_MCT( nKeyAlg, pKey, pCT, jsonRes, bWin );
    }
    else if( strAlgMode == "CBC" )
    {
        ret = makeSymDecCBC_MCT( nKeyAlg, pKey, pIV, pCT, jsonRes, bWin );
    }
    else if( strAlgMode == "CTR" )
    {
        ret = makeSymDecCTR_MCT( nKeyAlg, pKey, pIV, pCT, jsonRes, bWin );
    }
    else if( strAlgMode == "OFB" )
    {
        ret = makeSymDecOFB_MCT( nKeyAlg, pKey, pIV, pCT, jsonRes, bWin );
    }
    else if( strMode == "CFB" || strMode == "CFB128" )
    {
        ret = makeSymDecCFB_MCT( nKeyAlg, pKey, pIV, pCT, jsonRes, bWin );
    }
    else
    {
        ret = -1;
    }

    return ret;
}

int CAVPDlg::makeSymECB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pPT, QJsonArray& jsonRes, bool bWin )
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;

    int i = 0;
    int j = 0;
    int ret = 0;

    BIN binKey[100 + 1];
    BIN binPT[1000 + 1];
    BIN binCT[1000 + 1];

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = CKM_AES_ECB;

    memset( &binKey, 0x00, sizeof(BIN) * 101 );
    memset( &binPT, 0x00, sizeof(BIN) * 1001 );
    memset( &binCT, 0x00, sizeof(BIN) * 1001 );

    JS_BIN_copy( &binKey[0], pKey );
    JS_BIN_copy( &binPT[0], pPT );

    for( i = 0; i < 100; i++ )
    {
        QJsonObject jObj;

        if( bWin )
        {
            mMCT_SymCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mMCT_SymLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mMCT_SymLastPTText->setText( getHexString(binPT[0].pVal, binPT[0].nLen));
            }
        }

        update();

        logRsp( QString("COUNT = %1").arg(i));
        logRsp( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        logRsp( QString("PT = %1").arg(getHexString(binPT[0].pVal, binPT[0].nLen)));

        long hKey = -1;

        ret = createKey( nKeyAlg, &binKey[i], &hKey );
        if( ret != 0 ) goto end;

        for( j = 0; j < 1000; j++ )
        {
            memset( sOut, 0x00, sizeof(sOut ));
            nOutLen = sizeof( sOut );
            ret = pAPI->EncryptInit( hSession, &sMech, hKey );
            if( ret != 0 ) goto end;

            JS_BIN_reset( &binCT[j] );
            ret = pAPI->Encrypt( hSession, binPT[j].pVal, binPT[j].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
            JS_BIN_set( &binCT[j], sOut, nOutLen );

            if( ret != 0 ) goto end;

            JS_BIN_reset( &binPT[j+1] );
            JS_BIN_copy( &binPT[j+1], &binCT[j] );
        }

        ret = pAPI->DestroyObject( hSession, hKey );
        if( ret != 0 ) goto end;

        j = j - 1;

        if( bWin )
        {
            if( i == 0 )
            {
                mMCT_SymCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
            else if( i == 99 )
            {
                mMCT_SymLastCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
        }

        logRsp( QString("CT = %1").arg(getHexString(binCT[j].pVal, binCT[j].nLen)));
        logRsp( "" );

        jObj["ct"] = getHexString( &binCT[j] );
        jObj["key"] = getHexString( &binKey[i] );
        jObj["pt"] = getHexString( &binPT[0] );

        if( pKey->nLen == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binCT[j] );
        }
        else if( pKey->nLen == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binCT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( pKey->nLen == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binCT[j-1] );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binPT[0] );
        JS_BIN_copy( &binPT[0], &binCT[j]);

        jsonRes.insert( i, jObj );
    }


end :
    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i] );
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }

    return ret;
}

int CAVPDlg::makeSymCBC_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin )
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;

    int i = 0;
    int j = 0;
    int ret = 0;

    BIN binKey[100 + 1];
    BIN binIV[100 + 1];
    BIN binPT[1000 + 1];
    BIN binCT[1000 + 1];

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = CKM_AES_ECB;

    memset( &binKey, 0x00, sizeof(BIN) * 101 );
    memset( &binIV, 0x00, sizeof(BIN) * 101 );
    memset( &binPT, 0x00, sizeof(BIN) * 1001 );
    memset( &binCT, 0x00, sizeof(BIN) * 1001 );

    JS_BIN_copy( &binKey[0], pKey );
    JS_BIN_copy( &binIV[0], pIV );
    JS_BIN_copy( &binPT[0], pPT );

    int nMech = CKM_AES_ECB;

    for( i = 0; i < 100; i++ )
    {
        QJsonObject jObj;

        if( bWin )
        {
            mMCT_SymCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mMCT_SymLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mMCT_SymLastIVText->setText(getHexString(binIV[i].pVal, binIV[i].nLen));
                mMCT_SymLastPTText->setText( getHexString(binPT[0].pVal, binPT[0].nLen));
            }
        }

        update();

        logRsp( QString("COUNT = %1").arg(i));
        logRsp( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        logRsp( QString("IV = %1").arg( getHexString(binIV[i].pVal, binIV[i].nLen)));
        logRsp( QString("PT = %1").arg(getHexString(binPT[0].pVal, binPT[0].nLen)));

        long hKey = -1;
        ret = createKey( nKeyAlg, &binKey[i], &hKey );

        if( ret != 0 ) goto end;

        for( j = 0; j < 1000; j++ )
        {
            BIN binXOR = {0,0};
            BIN binParam = {0,0};

            if( j == 0 )
                JS_BIN_XOR( &binXOR, &binPT[j], &binIV[i] );
            else
                JS_BIN_XOR( &binXOR, &binPT[j], &binCT[j-1] );

            ret = pAPI->EncryptInit( hSession, &sMech, hKey );
            if( ret != 0 ) goto end;

            JS_BIN_reset( &binCT[j] );

            nOutLen = sizeof(sOut);
            memset( sOut, 0x00, nOutLen );

            ret = pAPI->Encrypt( hSession, binXOR.pVal, binXOR.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
            JS_BIN_set( &binCT[j], sOut, nOutLen );

            if( ret != 0 ) goto end;

            JS_BIN_reset( &binXOR );
            JS_BIN_reset( &binParam );

            if( j == 0 )
            {
                JS_BIN_reset( &binPT[j+1]);
                JS_BIN_copy( &binPT[j+1], &binIV[i] );
            }
            else
            {
                JS_BIN_reset( &binPT[j+1] );
                JS_BIN_copy( &binPT[j+1], &binCT[j-1] );
            }
        }

        ret = pAPI->DestroyObject( hSession, hKey );
        if( ret != 0 ) goto end;

        j = j - 1;

        if( bWin )
        {
            if( i == 0 )
            {
                mMCT_SymCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
            else if( i == 99 )
            {
                mMCT_SymLastCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
        }

        logRsp( QString("CT = %1").arg(getHexString(binCT[j].pVal, binCT[j].nLen)));
        logRsp( "" );

        jObj["ct"] = getHexString( &binCT[j] );
        jObj["iv"] = getHexString( &binIV[i] );
        jObj["key"] = getHexString( &binKey[i] );
        jObj["pt"] = getHexString( &binPT[0] );


        if( pKey->nLen == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binCT[j] );
        }
        else if( pKey->nLen == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binCT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( pKey->nLen == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binCT[j-1] );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binIV[i+1] );
        JS_BIN_copy( &binIV[i+1], &binCT[j] );
        JS_BIN_reset( &binPT[0] );
        JS_BIN_copy( &binPT[0], &binCT[j-1]);

        jsonRes.insert( i, jObj );
    }

end :
    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i] );
        JS_BIN_reset( &binIV[i] );
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }

    return ret;
}

int CAVPDlg::makeSymCTR_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin )
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;

    int i = 0;
    int j = 0;
    int ret = 0;

    BIN binKey[100+1];
    BIN binCTR = {0,0};
    BIN binPT[1000+1];
    BIN binCT[1000+1];

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = CKM_AES_ECB;

    memset( &binKey, 0x00, sizeof(BIN) * 101 );
    memset( &binPT, 0x00, sizeof(BIN) * 1001 );
    memset( &binCT, 0x00, sizeof(BIN) * 1001 );

    JS_BIN_copy( &binKey[0], pKey );
    JS_BIN_copy( &binCTR, pIV );
    JS_BIN_copy( &binPT[0], pPT );

    for( i = 0; i < 100; i++ )
    {
        QJsonObject jObj;

        if( bWin )
        {
            mMCT_SymCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mMCT_SymLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mMCT_SymLastIVText->setText(getHexString( binCTR.pVal, binCTR.nLen ));
                mMCT_SymLastPTText->setText( getHexString(binPT[0].pVal, binPT[0].nLen));
            }
        }

        update();

        logRsp( QString("COUNT = %1").arg(i));
        logRsp( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        logRsp( QString("CTR = %1").arg( getHexString(binCTR.pVal, binCTR.nLen)));
        logRsp( QString("PT = %1").arg(getHexString(binPT[0].pVal, binPT[0].nLen)));

        long hKey = -1;
        ret = createKey( nKeyAlg, &binKey[i], &hKey );

        if( ret != 0 ) goto end;

        for( j = 0; j < 1000; j++ )
        {
            BIN binEnc = {0,0};
            BIN binParam = {0,0};

            ret = pAPI->EncryptInit( hSession, &sMech, hKey );
            if( ret != 0 ) goto end;

            nOutLen = sizeof(sOut);
            memset( sOut, 0x00, nOutLen );

            ret = pAPI->Encrypt( hSession, binCTR.pVal, binCTR.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
            JS_BIN_set( &binEnc, sOut, nOutLen );
            if( ret != 0 ) goto end;

            JS_BIN_reset( &binCT[j] );
            JS_BIN_XOR( &binCT[j], &binEnc, &binPT[j] );

            JS_BIN_reset( &binEnc );
            JS_BIN_reset( &binParam );

            JS_BIN_INC( &binCTR );


            JS_BIN_reset( &binPT[j+1] );
            JS_BIN_copy( &binPT[j+1], &binCT[j] );
        }

        ret = pAPI->DestroyObject( hSession, hKey );
        if( ret != 0 ) goto end;

        j = j - 1;

        if( bWin )
        {
            if( i == 0 )
            {
                mMCT_SymCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
            else if( i == 99 )
            {
                mMCT_SymLastCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
        }

        logRsp( QString("CT = %1").arg(getHexString(binCT[j].pVal, binCT[j].nLen)));
        logRsp( "" );

        jObj["ct"] = getHexString( &binCT[j] );
        jObj["iv"] = getHexString( &binCTR );
        jObj["key"] = getHexString( &binKey[i] );
        jObj["pt"] = getHexString( &binPT[0] );

        if( pKey->nLen == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binCT[j] );
        }
        else if( pKey->nLen == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binCT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( pKey->nLen == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binCT[j-1] );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binPT[0] );
        JS_BIN_copy( &binPT[0], &binCT[j]);

        jsonRes.insert( i, jObj );
    }


end :
    JS_BIN_reset( &binCTR );

    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i] );
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }

    return ret;
}

int CAVPDlg::makeSymCFB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin )
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;

    int i = 0;
    int j = 0;
    int ret = 0;

    BIN binKey[100 + 1];
    BIN binIV[100 + 1];
    BIN binPT[1000 + 1];
    BIN binCT[1000 + 1];

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = CKM_AES_ECB;

    memset( &binKey, 0x00, sizeof(BIN) * 101 );
    memset( &binIV, 0x00, sizeof(BIN) * 101 );
    memset( &binPT, 0x00, sizeof(BIN) * 1001 );
    memset( &binCT, 0x00, sizeof(BIN) * 1001 );

    JS_BIN_copy( &binKey[0], pKey );
    JS_BIN_copy( &binIV[0], pIV );
    JS_BIN_copy( &binPT[0], pPT );

    for( i = 0; i < 100; i++ )
    {
        QJsonObject jObj;

        if( bWin )
        {
            mMCT_SymCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mMCT_SymLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mMCT_SymLastIVText->setText(getHexString(binIV[i].pVal, binIV[i].nLen));
                mMCT_SymLastPTText->setText( getHexString(binPT[0].pVal, binPT[0].nLen));
            }
        }

        update();

        logRsp( QString("COUNT = %1").arg(i));
        logRsp( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        logRsp( QString("IV = %1").arg( getHexString(binIV[i].pVal, binIV[i].nLen)));
        logRsp( QString("PT = %1").arg(getHexString(binPT[0].pVal, binPT[0].nLen)));

        long hKey = -1;
        ret = createKey( nKeyAlg, &binKey[i], &hKey );

        if( ret != 0 ) goto end;

        for( j = 0; j < 1000; j++ )
        {
            BIN binEnc = {0,0};
            BIN binParam = {0,0};

            ret = pAPI->EncryptInit( hSession, &sMech, hKey );
            if( ret != 0 ) goto end;

            nOutLen = sizeof(sOut);
            memset( sOut, 0x00, nOutLen );

            if( j == 0 )
            {
                ret = pAPI->Encrypt( hSession, binIV[i].pVal, binIV[i].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                JS_BIN_set( &binEnc, sOut, nOutLen );
            }
            else
            {
                ret = pAPI->Encrypt( hSession, binCT[j-1].pVal, binCT[j-1].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                JS_BIN_set( &binEnc, sOut, nOutLen );
            }

            if( ret != 0 ) goto end;

            JS_BIN_reset( &binCT[j] );
            JS_BIN_XOR( &binCT[j], &binEnc, &binPT[j] );

            JS_BIN_reset( &binEnc );
            JS_BIN_reset( &binParam );

            if( j == 0 )
            {
                JS_BIN_reset( &binPT[j+1]);
                JS_BIN_copy( &binPT[j+1], &binIV[i] );
            }
            else
            {
                JS_BIN_reset( &binPT[j+1] );
                JS_BIN_copy( &binPT[j+1], &binCT[j-1] );
            }
        }

        ret = pAPI->DestroyObject( hSession, hKey );
        if( ret != 0 ) goto end;

        j = j - 1;

        if( bWin )
        {
            if( i == 0 )
            {
                mMCT_SymCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
            else if( i == 99 )
            {
                mMCT_SymLastCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
        }

        logRsp( QString("CT = %1").arg(getHexString(binCT[j].pVal, binCT[j].nLen)));
        logRsp( "" );

        jObj["ct"] = getHexString( &binCT[j] );
        jObj["iv"] = getHexString( &binIV[i] );
        jObj["key"] = getHexString( &binKey[i] );
        jObj["pt"] = getHexString( &binPT[0] );

        if( pKey->nLen == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binCT[j] );
        }
        else if( pKey->nLen == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binCT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( pKey->nLen == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binCT[j-1] );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binIV[i+1] );
        JS_BIN_copy( &binIV[i+1], &binCT[j] );
        JS_BIN_reset( &binPT[0] );
        JS_BIN_copy( &binPT[0], &binCT[j-1]);

        jsonRes.insert( i, jObj );
    }


end :
    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i] );
        JS_BIN_reset( &binIV[i] );
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }

    return ret;
}

int CAVPDlg::makeSymOFB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin )
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;

    int i = 0;
    int j = 0;
    int ret = 0;

    BIN binKey[100 + 1];
    BIN binIV[100 + 1];
    BIN binPT[1000 + 1];
    BIN binCT[1000 + 1];
    BIN binOT[1000 + 1];

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = CKM_AES_ECB;

    memset( &binKey, 0x00, sizeof(BIN) * 101 );
    memset( &binIV, 0x00, sizeof(BIN) * 101 );
    memset( &binPT, 0x00, sizeof(BIN) * 1001 );
    memset( &binCT, 0x00, sizeof(BIN) * 1001 );
    memset( &binOT, 0x00, sizeof(BIN) * 1001 );

    JS_BIN_copy( &binKey[0], pKey );
    JS_BIN_copy( &binIV[0], pIV );
    JS_BIN_copy( &binPT[0], pPT );

    for( i = 0; i < 100; i++ )
    {
        QJsonObject jObj;

        if( bWin )
        {
            mMCT_SymCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mMCT_SymLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mMCT_SymLastIVText->setText(getHexString(binIV[i].pVal, binIV[i].nLen));
                mMCT_SymLastPTText->setText( getHexString(binPT[0].pVal, binPT[0].nLen));
            }
        }

        update();

        logRsp( QString("COUNT = %1").arg(i));
        logRsp( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        logRsp( QString("IV = %1").arg( getHexString(binIV[i].pVal, binIV[i].nLen)));
        logRsp( QString("PT = %1").arg(getHexString(binPT[0].pVal, binPT[0].nLen)));

        long hKey = -1;
        ret = createKey( nKeyAlg, &binKey[i], &hKey );
        if( ret != 0 ) goto end;

        for( j = 0; j < 1000; j++ )
        {

            BIN binParam = {0,0};

            ret = pAPI->EncryptInit( hSession, &sMech, hKey );
            if( ret != 0 ) goto end;

            JS_BIN_reset( &binOT[j] );
            nOutLen = sizeof(sOut);
            memset( sOut, 0x00, nOutLen );

            if( j == 0 )
            {
                ret = pAPI->Encrypt( hSession, binIV[i].pVal, binIV[i].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                JS_BIN_set( &binOT[j], sOut, nOutLen );
            }
            else
            {
                ret = pAPI->Encrypt( hSession, binOT[j-1].pVal, binOT[j-1].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                JS_BIN_set( &binOT[j], sOut, nOutLen );
            }

            if( ret != 0 ) goto end;

            JS_BIN_reset( &binParam );

            JS_BIN_reset( &binCT[j] );
            JS_BIN_XOR( &binCT[j], &binPT[j], &binOT[j] );

            if( j == 0 )
            {
                JS_BIN_reset( &binPT[j+1]);
                JS_BIN_copy( &binPT[j+1], &binIV[i] );
            }
            else
            {
                JS_BIN_reset( &binPT[j+1] );
                JS_BIN_copy( &binPT[j+1], &binCT[j-1] );
            }
        }

        ret = pAPI->DestroyObject( hSession, hKey );
        if( ret != 0 ) goto end;

        j = j - 1;

        if( bWin )
        {
            if( i == 0 )
            {
                mMCT_SymCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
            else if( i == 99 )
            {
                mMCT_SymLastCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
        }

        logRsp( QString("CT = %1").arg(getHexString(binCT[j].pVal, binCT[j].nLen)));
        logRsp( "" );

        jObj["ct"] = getHexString( &binCT[j] );
        jObj["iv"] = getHexString( &binIV[i] );
        jObj["key"] = getHexString( &binKey[i] );
        jObj["pt"] = getHexString( &binPT[0] );

        if( pKey->nLen == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binCT[j] );
        }
        else if( pKey->nLen == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binCT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( pKey->nLen == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binCT[j-1] );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binIV[i+1] );
        JS_BIN_copy( &binIV[i+1], &binCT[j] );
        JS_BIN_reset( &binPT[0] );
        JS_BIN_copy( &binPT[0], &binCT[j-1]);

        jsonRes.insert( i, jObj );
    }



end :
    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i] );
        JS_BIN_reset( &binIV[i] );
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
        JS_BIN_reset( &binOT[i] );
    }

    return ret;
}


/* Need to support decrypt */
int CAVPDlg::makeSymDecECB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pCT, QJsonArray& jsonRes, bool bWin )
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;

    int i = 0;
    int j = 0;
    int ret = 0;

    BIN binKey[100 + 1];
    BIN binPT[1000 + 1];
    BIN binCT[1000 + 1];

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = CKM_AES_ECB;

    memset( &binKey, 0x00, sizeof(BIN) * 101 );
    memset( &binPT, 0x00, sizeof(BIN) * 1001 );
    memset( &binCT, 0x00, sizeof(BIN) * 1001 );

    JS_BIN_copy( &binKey[0], pKey );
    JS_BIN_copy( &binCT[0], pCT );

    for( i = 0; i < 100; i++ )
    {
        QJsonObject jObj;

        if( bWin )
        {
            mMCT_SymCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mMCT_SymLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mMCT_SymLastCTText->setText( getHexString(binCT[0].pVal, binCT[0].nLen));
            }
        }

        update();

        logRsp( QString("COUNT = %1").arg(i));
        logRsp( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        logRsp( QString("CT = %1").arg(getHexString(binCT[0].pVal, binCT[0].nLen)));

        jObj["ct"] = getHexString( &binCT[0] );
        jObj["key"] = getHexString( &binKey[i] );

        long hKey = -1;
        ret = createKey( nKeyAlg, &binKey[i], &hKey );
        if( ret != 0 ) goto end;

        for( j = 0; j < 1000; j++ )
        {
            ret = pAPI->EncryptInit( hSession, &sMech, hKey );
            if( ret != 0 ) goto end;

            JS_BIN_reset( &binPT[j] );

            memset( sOut, 0x00, sizeof(sOut ));
            nOutLen = sizeof( sOut );

            ret = pAPI->Encrypt( hSession, binCT[j].pVal, binCT[j].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
            JS_BIN_set( &binPT[j], sOut, nOutLen );
            if( ret != 0 ) goto end;

            JS_BIN_reset( &binCT[j+1] );
            JS_BIN_copy( &binCT[j+1], &binPT[j] );
        }

        ret = pAPI->DestroyObject( hSession, hKey );
        if( ret != 0 ) goto end;

        j = j - 1;

        if( bWin )
        {
            if( i == 0 )
            {
                mMCT_SymPTText->setText( getHexString(binPT[j].pVal, binPT[j].nLen) );
            }
            else if( i == 99 )
            {
                mMCT_SymLastPTText->setText( getHexString(binPT[j].pVal, binPT[j].nLen) );
            }
        }

        logRsp( QString("PT = %1").arg(getHexString(binPT[j].pVal, binPT[j].nLen)));
        logRsp( "" );

        jObj["pt"] = getHexString( &binPT[j] );

        if( pKey->nLen == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binPT[j] );
        }
        else if( pKey->nLen == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binPT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binPT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( pKey->nLen == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binPT[j-1] );
            JS_BIN_appendBin( &binTmp, &binPT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binCT[0] );
        JS_BIN_copy( &binCT[0], &binPT[j]);

        jsonRes.insert( i, jObj );
    }


end :
    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i] );
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }

    return ret;
}

int CAVPDlg::makeSymDecCBC_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin )
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;

    int i = 0;
    int j = 0;
    int ret = 0;

    BIN binKey[100 + 1];
    BIN binIV[100 + 1];
    BIN binPT[1000 + 1];
    BIN binCT[1000 + 1];

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = CKM_AES_ECB;

    memset( &binKey, 0x00, sizeof(BIN) * 101 );
    memset( &binIV, 0x00, sizeof(BIN) * 101 );
    memset( &binPT, 0x00, sizeof(BIN) * 1001 );
    memset( &binCT, 0x00, sizeof(BIN) * 1001 );

    JS_BIN_copy( &binKey[0], pKey );
    JS_BIN_copy( &binIV[0], pIV );
    JS_BIN_copy( &binCT[0], pCT );

    for( i = 0; i < 100; i++ )
    {
        QJsonObject jObj;

        if( bWin )
        {
            mMCT_SymCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mMCT_SymLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mMCT_SymLastIVText->setText(getHexString(binIV[i].pVal, binIV[i].nLen));
                mMCT_SymLastCTText->setText( getHexString(binCT[0].pVal, binCT[0].nLen));
            }
        }

        update();

        logRsp( QString("COUNT = %1").arg(i));
        logRsp( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        logRsp( QString("IV = %1").arg( getHexString(binIV[i].pVal, binIV[i].nLen)));
        logRsp( QString("CT = %1").arg(getHexString(binCT[0].pVal, binCT[0].nLen)));

        jObj["ct"] = getHexString( &binCT[0] );
        jObj["iv"] = getHexString( &binIV[i] );
        jObj["key"] = getHexString( &binKey[i] );

        long hKey = -1;
        ret = createKey( nKeyAlg, &binKey[i], &hKey );

        if( ret != 0 ) goto end;

        for( j = 0; j < 1000; j++ )
        {
            BIN binDec = {0,0};
            BIN binParam = {0,0};

            ret = pAPI->EncryptInit( hSession, &sMech, hKey );
            if( ret != 0 ) goto end;

            JS_BIN_reset( &binPT[j] );

            nOutLen = sizeof(sOut);
            memset( sOut, 0x00, nOutLen );

            ret = pAPI->Encrypt( hSession, binCT[j].pVal, binCT[j].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
            JS_BIN_set( &binDec, sOut, nOutLen );

            if( ret != 0 ) goto end;

            if( j == 0 )
                JS_BIN_XOR( &binPT[j], &binDec, &binIV[i] );
            else
                JS_BIN_XOR( &binPT[j], &binDec, &binCT[j-1] );

            JS_BIN_reset( &binDec );
            JS_BIN_reset( &binParam );

            if( j == 0 )
            {
                JS_BIN_reset( &binCT[j+1]);
                JS_BIN_copy( &binCT[j+1], &binIV[i] );
            }
            else
            {
                JS_BIN_reset( &binCT[j+1] );
                JS_BIN_copy( &binCT[j+1], &binPT[j-1] );
            }
        }

        ret = pAPI->DestroyObject( hSession, hKey );
        if( ret != 0 ) goto end;

        j = j - 1;

        if( bWin )
        {
            if( i == 0 )
            {
                mMCT_SymPTText->setText( getHexString(binPT[j].pVal, binPT[j].nLen) );
            }
            else if( i == 99 )
            {
                mMCT_SymLastPTText->setText( getHexString(binPT[j].pVal, binPT[j].nLen) );
            }
        }

        logRsp( QString("PT = %1").arg(getHexString(binPT[j].pVal, binPT[j].nLen)));
        logRsp( "" );

        jObj["pt"] = getHexString( &binPT[j] );

        if( pKey->nLen == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binPT[j] );
        }
        else if( pKey->nLen == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binPT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binPT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( pKey->nLen == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binPT[j-1] );
            JS_BIN_appendBin( &binTmp, &binPT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binIV[i+1] );
        JS_BIN_copy( &binIV[i+1], &binPT[j] );
        JS_BIN_reset( &binCT[0] );
        JS_BIN_copy( &binCT[0], &binPT[j-1]);

        jsonRes.insert( i, jObj );
    }

end :
    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i] );
        JS_BIN_reset( &binIV[i] );
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }

    return ret;
}

int CAVPDlg::makeSymDecCTR_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin )
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;

    int i = 0;
    int j = 0;
    int ret = 0;

    BIN binKey[100+1];
    BIN binCTR = {0,0};
    BIN binPT[1000+1];
    BIN binCT[1000+1];

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = CKM_AES_ECB;

    memset( &binKey, 0x00, sizeof(BIN) * 101 );
    memset( &binPT, 0x00, sizeof(BIN) * 1001 );
    memset( &binCT, 0x00, sizeof(BIN) * 1001 );

    JS_BIN_copy( &binKey[0], pKey );
    JS_BIN_copy( &binCTR, pIV );
    JS_BIN_copy( &binCT[0], pCT );

    for( i = 0; i < 100; i++ )
    {
        QJsonObject jObj;

        if( bWin )
        {
            mMCT_SymCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mMCT_SymLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mMCT_SymLastIVText->setText(getHexString( binCTR.pVal, binCTR.nLen ));
                mMCT_SymLastCTText->setText( getHexString(binCT[0].pVal, binCT[0].nLen));
            }
        }

        update();

        logRsp( QString("COUNT = %1").arg(i));
        logRsp( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        logRsp( QString("CTR = %1").arg( getHexString(binCTR.pVal, binCTR.nLen)));
        logRsp( QString("CT = %1").arg(getHexString(binCT[0].pVal, binCT[0].nLen)));

        jObj["ct"] = getHexString( &binCT[0] );
        jObj["iv"] = getHexString( &binCTR );
        jObj["key"] = getHexString( &binKey[i] );

        long hKey = -1;
        ret = createKey( nKeyAlg, &binKey[i], &hKey );

        if( ret != 0 ) goto end;

        for( j = 0; j < 1000; j++ )
        {
            BIN binEnc = {0,0};
            BIN binParam = {0,0};

            ret = pAPI->EncryptInit( hSession, &sMech, hKey );
            if( ret != 0 ) goto end;

            ret = pAPI->Encrypt( hSession, binCTR.pVal, binCTR.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
            JS_BIN_set( &binEnc, sOut, nOutLen );
            if( ret != 0 ) goto end;

            JS_BIN_reset( &binPT[j] );
            JS_BIN_XOR( &binPT[j], &binEnc, &binCT[j] );

            JS_BIN_reset( &binEnc );
            JS_BIN_reset( &binParam );

            JS_BIN_INC( &binCTR );

            JS_BIN_reset( &binCT[j+1] );
            JS_BIN_copy( &binCT[j+1], &binPT[j] );

        }

        ret = pAPI->DestroyObject( hSession, hKey );
        if( ret != 0 ) goto end;

        j = j - 1;

        if( bWin )
        {
            if( i == 0 )
            {
                mMCT_SymPTText->setText( getHexString(binPT[j].pVal, binPT[j].nLen) );
            }
            else if( i == 99 )
            {
                mMCT_SymLastPTText->setText( getHexString(binPT[j].pVal, binPT[j].nLen) );
            }
        }

        logRsp( QString("PT = %1").arg(getHexString(binPT[j].pVal, binPT[j].nLen)));
        logRsp( "" );

        jObj["pt"] = getHexString( &binPT[j] );

        if( pKey->nLen == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binPT[j] );
        }
        else if( pKey->nLen == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binPT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binPT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( pKey->nLen == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binPT[j-1] );
            JS_BIN_appendBin( &binTmp, &binPT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binCT[0] );
        JS_BIN_copy( &binCT[0], &binPT[j]);

        jsonRes.insert( i, jObj );
    }


end :
    JS_BIN_reset( &binCTR );

    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i] );
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }

    return ret;
}

int CAVPDlg::makeSymDecCFB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin )
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;

    int i = 0;
    int j = 0;
    int ret = 0;

    BIN binKey[100 + 1];
    BIN binIV[100 + 1];
    BIN binPT[1000 + 1];
    BIN binCT[1000 + 1];

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = CKM_AES_ECB;

    memset( &binKey, 0x00, sizeof(BIN) * 101 );
    memset( &binIV, 0x00, sizeof(BIN) * 101 );
    memset( &binPT, 0x00, sizeof(BIN) * 1001 );
    memset( &binCT, 0x00, sizeof(BIN) * 1001 );

    JS_BIN_copy( &binKey[0], pKey );
    JS_BIN_copy( &binIV[0], pIV );
    JS_BIN_copy( &binCT[0], pCT );

    for( i = 0; i < 100; i++ )
    {
        QJsonObject jObj;

        if( bWin )
        {
            mMCT_SymCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mMCT_SymLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mMCT_SymLastIVText->setText(getHexString(binIV[i].pVal, binIV[i].nLen));
                mMCT_SymLastCTText->setText( getHexString(binCT[0].pVal, binCT[0].nLen));
            }
        }

        update();

        logRsp( QString("COUNT = %1").arg(i));
        logRsp( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        logRsp( QString("IV = %1").arg( getHexString(binIV[i].pVal, binIV[i].nLen)));
        logRsp( QString("CT = %1").arg(getHexString(binCT[0].pVal, binCT[0].nLen)));

        jObj["ct"] = getHexString( &binCT[0] );
        jObj["iv"] = getHexString( &binIV[i] );
        jObj["key"] = getHexString( &binKey[i] );

        long hKey = -1;
        ret = createKey( nKeyAlg, &binKey[i], &hKey );

        if( ret != 0 ) goto end;

        for( j = 0; j < 1000; j++ )
        {
            BIN binDec = {0,0};
            BIN binParam = {0,0};

            ret = pAPI->EncryptInit( hSession, &sMech, hKey );
            if( ret != 0 ) goto end;


            if( j == 0 )
            {
                ret = pAPI->Encrypt( hSession, binIV[i].pVal, binIV[i].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                JS_BIN_set( &binDec, sOut, nOutLen );
            }
            else
            {
                ret = pAPI->Encrypt( hSession, binCT[j-1].pVal, binCT[j-1].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                JS_BIN_set( &binDec, sOut, nOutLen );
            }

            if( ret != 0 ) goto end;

            JS_BIN_reset( &binPT[j] );
            JS_BIN_XOR( &binPT[j], &binDec, &binCT[j] );
            JS_BIN_reset( &binDec );
            JS_BIN_reset( &binParam );

            if( j == 0 )
            {
                JS_BIN_reset( &binCT[j+1]);
                JS_BIN_copy( &binCT[j+1], &binIV[i] );
            }
            else
            {
                JS_BIN_reset( &binCT[j+1] );
                JS_BIN_copy( &binCT[j+1], &binPT[j-1] );
            }
        }

        ret = pAPI->DestroyObject( hSession, hKey );
        if( ret != 0 ) goto end;

        j = j - 1;

        if( bWin )
        {
            if( i == 0 )
            {
                mMCT_SymPTText->setText( getHexString(binPT[j].pVal, binPT[j].nLen) );
            }
            else if( i == 99 )
            {
                mMCT_SymLastPTText->setText( getHexString(binPT[j].pVal, binPT[j].nLen) );
            }
        }

        logRsp( QString("PT = %1").arg(getHexString(binPT[j].pVal, binPT[j].nLen)));
        logRsp( "" );

        jObj["pt"] = getHexString( &binPT[j] );

        if( pKey->nLen == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binPT[j] );
        }
        else if( pKey->nLen == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binPT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binPT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( pKey->nLen == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binPT[j-1] );
            JS_BIN_appendBin( &binTmp, &binPT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binIV[i+1] );
        JS_BIN_copy( &binIV[i+1], &binPT[j] );
        JS_BIN_reset( &binCT[0] );
        JS_BIN_copy( &binCT[0], &binPT[j-1]);

        jsonRes.insert( i, jObj );
    }


end :
    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i] );
        JS_BIN_reset( &binIV[i] );
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }

    return ret;
}

int CAVPDlg::makeSymDecOFB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin )
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;

    int i = 0;
    int j = 0;
    int ret = 0;

    BIN binKey[100 + 1];
    BIN binIV[100 + 1];
    BIN binPT[1000 + 1];
    BIN binCT[1000 + 1];
    BIN binOT[1000 + 1];

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = CKM_AES_ECB;

    memset( &binKey, 0x00, sizeof(BIN) * 101 );
    memset( &binIV, 0x00, sizeof(BIN) * 101 );
    memset( &binPT, 0x00, sizeof(BIN) * 1001 );
    memset( &binCT, 0x00, sizeof(BIN) * 1001 );
    memset( &binOT, 0x00, sizeof(BIN) * 1001 );

    JS_BIN_copy( &binKey[0], pKey );
    JS_BIN_copy( &binIV[0], pIV );
    JS_BIN_copy( &binCT[0], pCT );

    for( i = 0; i < 100; i++ )
    {
        QJsonObject jObj;

        if( bWin )
        {
            mMCT_SymCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mMCT_SymLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mMCT_SymLastIVText->setText(getHexString(binIV[i].pVal, binIV[i].nLen));
                mMCT_SymLastCTText->setText( getHexString(binCT[0].pVal, binCT[0].nLen));
            }
        }

        update();

        logRsp( QString("COUNT = %1").arg(i));
        logRsp( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        logRsp( QString("IV = %1").arg( getHexString(binIV[i].pVal, binIV[i].nLen)));
        logRsp( QString("CT = %1").arg(getHexString(binCT[0].pVal, binCT[0].nLen)));

        jObj["ct"] = getHexString( &binCT[0] );
        jObj["iv"] = getHexString( &binIV[i] );
        jObj["key"] = getHexString( &binKey[i] );

        long hKey = -1;
        ret = createKey( nKeyAlg, &binKey[i], &hKey );

        if( ret != 0 ) goto end;

        for( j = 0; j < 1000; j++ )
        {
            BIN binParam = {0,0};

            ret = pAPI->EncryptInit( hSession, &sMech, hKey );
            if( ret != 0 ) goto end;

            JS_BIN_reset( &binOT[j] );

            if( j == 0 )
            {
                ret = pAPI->Encrypt( hSession, binIV[i].pVal, binIV[i].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                JS_BIN_set( &binOT[j], sOut, nOutLen );
            }
            else
            {
                ret = pAPI->Encrypt( hSession, binOT[j-1].pVal, binOT[j-1].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                JS_BIN_set( &binOT[j], sOut, nOutLen );
            }

            if( ret != 0 ) goto end;

            JS_BIN_reset( &binParam );

            JS_BIN_reset( &binPT[j] );
            JS_BIN_XOR( &binPT[j], &binCT[j], &binOT[j] );

            if( j == 0 )
            {
                JS_BIN_reset( &binCT[j+1]);
                JS_BIN_copy( &binCT[j+1], &binIV[i] );
            }
            else
            {
                JS_BIN_reset( &binCT[j+1] );
                JS_BIN_copy( &binCT[j+1], &binPT[j-1] );
            }
        }

        ret = pAPI->DestroyObject( hSession, hKey );
        if( ret != 0 ) goto end;

        j = j - 1;

        if( bWin )
        {
            if( i == 0 )
            {
                mMCT_SymPTText->setText( getHexString(binPT[j].pVal, binPT[j].nLen) );
            }
            else if( i == 99 )
            {
                mMCT_SymLastPTText->setText( getHexString(binPT[j].pVal, binPT[j].nLen) );
            }
        }

        logRsp( QString("PT = %1").arg(getHexString(binPT[j].pVal, binPT[j].nLen)));
        logRsp( "" );

        jObj["pt"] = getHexString( &binPT[j] );

        if( pKey->nLen == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binPT[j] );
        }
        else if( pKey->nLen == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binPT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binPT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( pKey->nLen == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binPT[j-1] );
            JS_BIN_appendBin( &binTmp, &binPT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binIV[i+1] );
        JS_BIN_copy( &binIV[i+1], &binPT[j] );
        JS_BIN_reset( &binCT[0] );
        JS_BIN_copy( &binCT[0], &binPT[j-1]);

        jsonRes.insert( i, jObj );
    }



end :
    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i] );
        JS_BIN_reset( &binIV[i] );
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
        JS_BIN_reset( &binOT[i] );
    }

    return ret;
}


int CAVPDlg::makeHash_MCT( const QString strAlg, const BIN *pSeed, QJsonArray& jsonRes, bool bWin )
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;

    int ret = 0;
    BIN binMD[1003 + 1];
    BIN binM[1003 + 1];
    BIN binSeed = {0,0};

    memset( &sMech, 0x00, sizeof(sMech));

    if( strAlg == "SHA-1" )
        sMech.mechanism = CKM_SHA_1;
    else if( strAlg == "SHA2-224" )
        sMech.mechanism = CKM_SHA224;
    else if( strAlg == "SHA2-256" )
        sMech.mechanism = CKM_SHA256;
    else if( strAlg == "SHA2-384" )
        sMech.mechanism = CKM_SHA384;
    else if( strAlg == "SHA2-512" )
        sMech.mechanism = CKM_SHA512;
    else
    {
        manApplet->warningBox( QString("Invalid algorithm: %1").arg( strAlg ), this );
        return -1;
    }

    memset( &binMD, 0x00, sizeof(BIN) * 1004 );
    memset( &binM, 0x00, sizeof(BIN) * 1004 );

    JS_BIN_copy( &binSeed, pSeed );

    for( int j = 0; j < 100; j++ )
    {
        QJsonObject jObj;

        if( bWin )
        {
            mMCT_HashCountText->setText( QString("%1").arg(j));
        }

        JS_BIN_reset( &binMD[0] );
        JS_BIN_reset( &binMD[1] );
        JS_BIN_reset( &binMD[2] );

        JS_BIN_copy( &binMD[0], &binSeed );
        JS_BIN_copy( &binMD[1], &binSeed );
        JS_BIN_copy( &binMD[2], &binSeed );

        for( int i = 3; i < 1003; i++ )
        {
            JS_BIN_reset( &binM[i] );
            JS_BIN_appendBin( &binM[i], &binMD[i-3] );
            JS_BIN_appendBin( &binM[i], &binMD[i-2] );
            JS_BIN_appendBin( &binM[i], &binMD[i-1] );

            ret = pAPI->DigestInit( hSession, &sMech );
            if( ret != 0 ) goto end;

            JS_BIN_reset( &binMD[i] );

            nOutLen = sizeof(sOut);
            memset( sOut, 0x00, nOutLen );

            ret = pAPI->Digest( hSession, binM[i].pVal, binM[i].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
            JS_BIN_set( &binMD[i], sOut, nOutLen );
        }

        JS_BIN_reset( &binMD[j] );
        JS_BIN_reset( &binSeed );
        JS_BIN_copy( &binSeed, &binMD[1002] );
        JS_BIN_copy( &binMD[j], &binSeed );

        if( bWin )
        {
            if( j == 0 )
                mMCT_HashFirstMDText->setText( getHexString(binMD[j].pVal, binMD[j].nLen));

            if( j == 99 )
                mMCT_HashLastMDText->setText( getHexString(binMD[j].pVal, binMD[j].nLen));
        }

        logRsp( QString( "COUNT = %1").arg(j));
        logRsp( QString( "MD = %1").arg(getHexString(binMD[j].pVal, binMD[j].nLen)));
        logRsp( "" );

        jObj["md"] = getHexString( &binMD[j] );
        jsonRes.insert( j, jObj );
    }


end :
    for( int i = 0; i < 1004; i++ )
    {
        JS_BIN_reset( &binMD[i] );
        JS_BIN_reset( &binM[i] );
    }

    JS_BIN_reset( &binSeed );

    return ret;
}

int CAVPDlg::makeHash_AlternateMCT( const QString strAlg, const BIN *pSeed, QJsonArray& jsonRes, bool bWin )
{
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;

    int ret = 0;
    BIN binMD[1003 + 1];
    BIN binM[1003 + 1];
    BIN binSeed = {0,0};

    int nInitSeedLen = 0;

    memset( &sMech, 0x00, sizeof(sMech));

    if( strAlg == "SHA-1" )
        sMech.mechanism = CKM_SHA_1;
    else if( strAlg == "SHA2-224" )
        sMech.mechanism = CKM_SHA224;
    else if( strAlg == "SHA2-256" )
        sMech.mechanism = CKM_SHA256;
    else if( strAlg == "SHA2-384" )
        sMech.mechanism = CKM_SHA384;
    else if( strAlg == "SHA2-512" )
        sMech.mechanism = CKM_SHA512;
    else
    {
        manApplet->warningBox( QString("Invalid algorithm: %1").arg( strAlg ), this );
        return -1;
    }


    memset( &binMD, 0x00, sizeof(BIN) * 1004 );
    memset( &binM, 0x00, sizeof(BIN) * 1004 );

    JS_BIN_copy( &binSeed, pSeed );
    nInitSeedLen = binSeed.nLen;

    for( int j = 0; j < 100; j++ )
    {
        QJsonObject jObj;

        if( bWin )
        {
            mMCT_HashCountText->setText( QString("%1").arg(j));
        }

        JS_BIN_reset( &binMD[0] );
        JS_BIN_reset( &binMD[1] );
        JS_BIN_reset( &binMD[2] );

        JS_BIN_copy( &binMD[0], &binSeed );
        JS_BIN_copy( &binMD[1], &binSeed );
        JS_BIN_copy( &binMD[2], &binSeed );

        for( int i = 3; i < 1003; i++ )
        {
            JS_BIN_reset( &binM[i] );
            JS_BIN_appendBin( &binM[i], &binMD[i-3] );
            JS_BIN_appendBin( &binM[i], &binMD[i-2] );
            JS_BIN_appendBin( &binM[i], &binMD[i-1] );

            ret = pAPI->DigestInit( hSession, &sMech );
            if( ret != 0 ) goto end;

            JS_BIN_reset( &binMD[i] );

            if( binM[i].nLen >= nInitSeedLen )
                binM[i].nLen = nInitSeedLen;
            else
            {
                int nDiff = nInitSeedLen - binM[i].nLen;
                JS_BIN_appendCh( &binM[i], 0x00, nDiff );
            }

            nOutLen = sizeof(sOut);
            memset( sOut, 0x00, nOutLen );

            ret = pAPI->Digest( hSession, binM[i].pVal, binM[i].nLen, sOut, (CK_ULONG_PTR)&nOutLen );
            JS_BIN_set( &binMD[i], sOut, nOutLen );
        }

        JS_BIN_reset( &binMD[j] );
        JS_BIN_reset( &binSeed );
        JS_BIN_copy( &binSeed, &binMD[1002] );
        JS_BIN_copy( &binMD[j], &binSeed );

        if( bWin )
        {
            if( j == 0 )
                mMCT_HashFirstMDText->setText( getHexString(binMD[j].pVal, binMD[j].nLen));

            if( j == 99 )
                mMCT_HashLastMDText->setText( getHexString(binMD[j].pVal, binMD[j].nLen));
        }

        logRsp( QString( "COUNT = %1").arg(j));
        logRsp( QString( "MD = %1").arg(getHexString(binMD[j].pVal, binMD[j].nLen)));
        logRsp( "" );

        jObj["md"] = getHexString( &binMD[j] );
        jsonRes.insert( j, jObj );
    }


end :
    for( int i = 0; i < 1004; i++ )
    {
        JS_BIN_reset( &binMD[i] );
        JS_BIN_reset( &binM[i] );
    }

    JS_BIN_reset( &binSeed );

    return ret;
}

void CAVPDlg::saveJsonRsp( const QJsonDocument& pJsonDoc )
{
    QDir dir;
    QString strRspPath = mRspPathText->text();
    QString strReqPath = mACVP_ReqPathText->text();

    QFileInfo fileInfo( strReqPath );
    QString strBaseName = fileInfo.baseName();

    QString strSaveName;

    QDateTime date;
    date.setTime_t( time(NULL));

    if( strRspPath.length() > 0 ) strRspPath += "/";

    strRspPath += "acvp_rsp";

    if( dir.exists( strRspPath ) == false )
        dir.mkdir( strRspPath );


    strSaveName = QString( "%1/%2_%3.json" )
                      .arg( strRspPath )
                      .arg( strBaseName )
                      .arg( date.toString( "yyyy_MM_dd_HHmmss" ));

    QFile saveFile( strSaveName );
    saveFile.open(QFile::WriteOnly | QFile::Append| QFile::Text );
    saveFile.write( pJsonDoc.toJson() );
    saveFile.close();

    manApplet->messageBox( tr( "%1 file save successfully").arg( strSaveName ), this );

}

int CAVPDlg::readJsonReq( const QString strPath, QJsonDocument& pJsonDoc )
{
    QFile jsonFile( strPath );
    manApplet->log( QString( "Json Path: %1").arg( strPath ));

    if( !jsonFile.open( QIODevice::ReadOnly))
    {
        manApplet->elog( QString( "fail to read json: %1").arg( strPath));
        return -1;
    }

    QByteArray fileByte = jsonFile.readAll();
    manApplet->log( QString("Json Size: %1").arg( fileByte.size() ));

    jsonFile.close();

    pJsonDoc = QJsonDocument::fromJson( fileByte );

    return 0;
}

int CAVPDlg::makeUnitJsonWork( const QString strAlg, const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    int nACVP_Type = -1;
    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    if( isSkipTestType( strTestType ) == true )
    {
        QJsonObject jSkipObj;
        jRspObject["tests"] = jSkipObj;
        jRspObject["tgId"] = nTgId;

        return 0;
    }

    nACVP_Type = getACVPType( strAlg );

    switch ( nACVP_Type ) {
    case kACVP_TYPE_BLOCK_CIPHER :
        ret = blockCipherJsonWork( strAlg, jObject, jRspObject );
        break;

    case kACVP_TYPE_HASH :
        ret = hashJsonWork( strAlg, jObject, jRspObject );
        break;

    case kACVP_TYPE_MAC :
        ret = macJsonWork( strAlg, jObject, jRspObject );
        break;

    case kACVP_TYPE_RSA :
        ret = rsaJsonWork( strMode, jObject, jRspObject );
        break;

    case kACVP_TYPE_ECDSA :
        ret = ecdsaJsonWork( strMode, jObject, jRspObject );
        break;

    case kACVP_TYPE_DRBG :
        ret = drbgJsonWork( strAlg, jObject, jRspObject );
        break;

    case kACVP_TYPE_KDA :
        ret = kdaJsonWork( strAlg, jObject, jRspObject );
        break;

    case kACVP_TYPE_EDDSA:
        ret = eddsaJsonWork( strMode, jObject, jRspObject );
        break;

    case kACVP_TYPE_DSA:
        ret = dsaJsonWork( strMode, jObject, jRspObject );
        break;

    default:
        ret = -1;
        manApplet->warnLog( QString( "Invalid Algorithm: %1" ).arg( strAlg ), this );
        break;
    }

    return ret;
}

bool CAVPDlg::isSkipTestType( const QString strTestType )
{
    if( mACVP_SkipLDTCheck->isChecked() == true )
        if( strTestType == "MCT" ) return true;

    return false;
}

int CAVPDlg::hashJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

int CAVPDlg::ecdsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

int CAVPDlg::eddsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

int CAVPDlg::rsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

int CAVPDlg::dsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

int CAVPDlg::macJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

int CAVPDlg::blockCipherJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

int CAVPDlg::kdaJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

int CAVPDlg::drbgJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

