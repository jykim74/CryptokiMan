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
#include "js_error.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "js_pki_eddsa.h"

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

int _getCKM_Cipher( const QString strAlg, const QString strMode )
{
    if( strAlg == "AES" )
    {
        if( strMode == "ECB" )
            return CKM_AES_ECB;
        else if( strMode == "CBC" )
            return CKM_AES_CBC;
        else if( strMode == "CTR" )
            return CKM_AES_CTR;
        else if( strMode == "OFB" )
            return CKM_AES_OFB;
        else if( strMode == "CFB" )
            return CKM_AES_CFB128;
        else if( strMode == "GCM" )
            return CKM_AES_GCM;
        else if( strMode == "CCM" )
            return CKM_AES_CCM;
    }
    else if( strAlg == "DES3" || strAlg == "3DES" )
    {
        if( strMode == "ECB" )
            return CKM_DES3_ECB;
        else if( strMode == "CBC" )
            return CKM_DES3_CBC;
    }

    return -1;
}

int _getCKM_HMAC( const QString strHash )
{
    if( strHash == "SHA1" || strHash == "SHA-1" )
        return CKM_SHA_1_HMAC;
    else if( strHash == "SHA224" )
        return CKM_SHA224_HMAC;
    else if( strHash == "SHA256" )
        return CKM_SHA256_HMAC;
    else if( strHash == "SHA384" )
        return CKM_SHA384_HMAC;
    else if( strHash == "SHA512" )
        return CKM_SHA512_HMAC;

    return -1;
}

int _getCKM_Hash( const QString strHash )
{
    if( strHash == "SHA1" || strHash == "SHA-1" )
        return CKM_SHA_1;
    else if( strHash == "SHA224" || strHash == "SHA2-224" )
        return CKM_SHA224;
    else if( strHash == "SHA256" || strHash == "SHA2-256" )
        return CKM_SHA256;
    else if( strHash == "SHA384" || strHash == "SHA2-384" )
        return CKM_SHA384;
    else if( strHash == "SHA512" || strHash == "SHA2-512" )
        return CKM_SHA512;;

    return -1;
}

int _getCKM_ECDSA( const QString strHash )
{
    if( strHash == "SHA1" || strHash == "SHA-1" )
        return CKM_ECDSA_SHA1;
    else if( strHash == "SHA224" )
        return CKM_ECDSA_SHA224;
    else if( strHash == "SHA256" )
        return CKM_ECDSA_SHA256;
    else if( strHash == "SHA384" )
        return CKM_ECDSA_SHA384;
    else if( strHash == "SHA512" )
        return CKM_ECDSA_SHA512;

    return -1;
}

int _getCKM_RSA( const QString strHash, bool bPSS )
{
    if( bPSS == true )
    {
        if( strHash == "SHA1" || strHash == "SHA-1" )
            return CKM_SHA1_RSA_PKCS_PSS;
        else if( strHash == "SHA224" || strHash == "SHA2-224" )
            return CKM_SHA224_RSA_PKCS_PSS;
        else if( strHash == "SHA256" || strHash == "SHA2-256" )
            return CKM_SHA256_RSA_PKCS_PSS;
        else if( strHash == "SHA384" || strHash == "SHA2-384" )
            return CKM_SHA384_RSA_PKCS_PSS;
        else if( strHash == "SHA512" || strHash == "SHA2-512" )
            return CKM_SHA512_RSA_PKCS_PSS;

        return CKM_RSA_PKCS_PSS;
    }
    else
    {
        if( strHash == "SHA1" || strHash == "SHA-1" )
            return CKM_SHA1_RSA_PKCS;
        else if( strHash == "SHA224" || strHash == "SHA2-224" )
            return CKM_SHA224_RSA_PKCS;
        else if( strHash == "SHA256" || strHash == "SHA2-256" )
            return CKM_SHA256_RSA_PKCS;
        else if( strHash == "SHA384" || strHash == "SHA2-384" )
            return CKM_SHA384_RSA_PKCS;
        else if( strHash == "SHA512" || strHash == "SHA2-512" )
            return CKM_SHA512_RSA_PKCS;

        return CKM_RSA_PKCS;
    }
}

static QString _getHashName( const QString strACVPHash )
{
    if( strACVPHash == "SHA-1" )
        return "SHA1";
    else if( strACVPHash == "SHA2-224" )
        return "SHA224";
    else if( strACVPHash == "SHA2-256" )
        return "SHA256";
    else if( strACVPHash == "SHA2-384" )
        return "SHA384";
    else if( strACVPHash == "SHA2-512" )
        return "SHA512";

    return "";
}

static QString _getECCurveName( const QString strACVPCurve )
{
    if( strACVPCurve == "P-256" )
        return "prime256v1";
    else if( strACVPCurve == "P-384" )
        return "secp384r1";
    else if( strACVPCurve == "P-521" )
        return "secp521r1";

    return "";
}

static int _getEdDSAType( const QString strACVPCurve )
{
    if( strACVPCurve == "ED-25519" )
        return JS_PKI_KEY_TYPE_ED25519;
    else if( strACVPCurve == "ED-448" )
        return JS_PKI_KEY_TYPE_ED448;

    return -1;
}

static int _getAlgMode( const QString strAlg, QString& strSymAlg, QString& strMode )
{
    QStringList strList = strAlg.split( "-" );

    if( strList.size() >= 3 )
    {
        strSymAlg = strList.at(1);
        strMode = strList.at(2);
    }
    else if( strList.size() == 2 )
    {
        strSymAlg = strList.at(0);
        strMode = strList.at(1);
    }
    else
    {
        return -1;
    }

    return 0;
}

static QString _getHashNameFromMAC( const QString strACVPMac )
{
    if( strACVPMac == "HMAC-SHA-1" )
        return "SHA1";
    else if( strACVPMac == "HMAC-SHA2-224" )
        return "SHA224";
    else if( strACVPMac == "HMAC-SHA2-256" )
        return "SHA256";
    else if( strACVPMac == "HMAC-SHA2-384" )
        return "SHA384";
    else if( strACVPMac == "HMAC-SHA2-512" )
        return "SHA512";

    return "";
}

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
    connect( mACVP_FindReqPathBtn, SIGNAL(clicked()), this, SLOT(clickACVPFindJson()));

    connect( mECCAlgCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeECCAlg(int)));
    connect( mRSAAlgCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeRSAAlg(int)));
    connect( mECCTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeECCType(int)));
    connect( mRSATypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeRSAType(int)));

    connect( mMCT_SymKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(MCT_KeyChanged(const QString&)));
    connect( mMCT_SymIVText, SIGNAL(textChanged(const QString&)), this, SLOT(MCT_IVChanged(const QString&)));
    connect( mMCT_SymPTText, SIGNAL(textChanged(const QString&)), this, SLOT(MCT_PTChanged(const QString&)));
    connect( mMCT_SymCTText, SIGNAL(textChanged(const QString&)), this, SLOT(MCT_CTChanged(const QString&)));

    connect( mMCT_SymLastKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(MCT_LastKeyChanged(const QString&)));
    connect( mMCT_SymLastIVText, SIGNAL(textChanged(const QString&)), this, SLOT(MCT_LastIVChanged(const QString&)));
    connect( mMCT_SymLastPTText, SIGNAL(textChanged(const QString&)), this, SLOT(MCT_LastPTChanged(const QString&)));
    connect( mMCT_SymLastCTText, SIGNAL(textChanged(const QString&)), this, SLOT(MCT_LastCTChanged(const QString&)));

    connect( mMCT_HashSeedText, SIGNAL(textChanged(const QString&)), this, SLOT(MCT_SeedChanged(const QString&)));
    connect( mMCT_HashFirstMDText, SIGNAL(textChanged(const QString&)), this, SLOT(MCT_FirstMDChanged(const QString&)));
    connect( mMCT_HashLastMDText, SIGNAL(textChanged(const QString&)), this, SLOT(MCT_LastMDChanged(const QString&)));

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

    connect( mACVP_SetTCIDCheck, SIGNAL(clicked()), this, SLOT(checkACVPSetTcId()));
    connect( mACVP_SetTGIDCheck, SIGNAL(clicked()), this, SLOT(checkACVPSetTgId()));

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
    mECCTypeCombo->clear();
    mECCTypeCombo->addItems( kECCTypeECDSA );

    mRSAAlgCombo->addItems( kRSAAlgList );
    mRSAHashCombo->addItems( kHashAlgList );
    mRSA_EText->setText( "65537" );
    mRSATypeCombo->clear();
    mRSATypeCombo->addItems( kRSATypeRSAES );

    checkACVPSetTcId();
    checkACVPSetTgId();

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

void CAVPDlg::clickACVPFindJson()
{
    QString strRspPath = mACVP_ReqPathText->text();
    if( strRspPath.length() < 1 ) strRspPath = manApplet->curPath();

    QString strFileName = findFile( this, JS_FILE_TYPE_JSON, strRspPath );
    if( strFileName.length() > 0 )
    {
        mACVP_ReqPathText->setText( strFileName );
    }
}

void CAVPDlg::changeECCAlg(int index)
{
    QString strAlg = mECCAlgCombo->currentText();

    mECCTypeCombo->clear();

    if( strAlg == "ECDSA" )
        mECCTypeCombo->addItems( kECCTypeECDSA );
    else
        mECCTypeCombo->addItems( kECCTypeECDH );
}

void CAVPDlg::changeRSAAlg(int index)
{
    QString strAlg = mRSAAlgCombo->currentText();

    mRSATypeCombo->clear();

    if( strAlg == "RSAES" )
        mRSATypeCombo->addItems( kRSATypeRSAES );
    else
        mRSATypeCombo->addItems( kRSATypeRSAPSS );
}

void CAVPDlg::changeECCType(int index)
{
    QString strType = mECCTypeCombo->currentText();

    if( strType == "SGT" || strType == "SVT" )
        mECCHashCombo->setEnabled(true);
    else
        mECCHashCombo->setEnabled(false);
}

void CAVPDlg::changeRSAType(int index)
{
    QString strType = mRSATypeCombo->currentText();

    if( strType == "SGT" || strType == "SVT" )
        mRSAHashCombo->setEnabled(true);
    else
        mRSAHashCombo->setEnabled(false);

    if( strType == "DET" )
    {
        mRSAObjectLabel->setEnabled( true );
        mRSA_DETPriKeyFindBtn->setEnabled(true);
        mRSA_DETPriKeyPathText->setEnabled(true);
    }
    else
    {
        mRSAObjectLabel->setEnabled( false );
        mRSA_DETPriKeyFindBtn->setEnabled(false);
        mRSA_DETPriKeyPathText->setEnabled(false);
    }
}

void CAVPDlg::checkACVPSetTgId()
{
    bool bVal = mACVP_SetTGIDCheck->isChecked();
    mACVP_SetTGIDText->setEnabled( bVal );
}

void CAVPDlg::checkACVPSetTcId()
{
    bool bVal = mACVP_SetTCIDCheck->isChecked();
    mACVP_SetTCIDText->setEnabled( bVal );
}

void CAVPDlg::MCT_KeyChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mMCT_SymKeyLenText->setText( QString("%1").arg(strLen));
}

void CAVPDlg::MCT_IVChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mMCT_SymIVLenText->setText( QString("%1").arg(strLen));
}

void CAVPDlg::MCT_PTChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mMCT_SymPTLenText->setText( QString("%1").arg(strLen));
}

void CAVPDlg::MCT_CTChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mMCT_SymCTLenText->setText( QString("%1").arg(strLen));
}

void CAVPDlg::MCT_LastKeyChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mMCT_SymLastKeyLenText->setText( QString("%1").arg(strLen));
}

void CAVPDlg::MCT_LastIVChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mMCT_SymLastIVLenText->setText( QString("%1").arg(strLen));
}

void CAVPDlg::MCT_LastPTChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mMCT_SymLastPTLenText->setText( QString("%1").arg(strLen));
}

void CAVPDlg::MCT_LastCTChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mMCT_SymLastCTLenText->setText( QString("%1").arg(strLen));
}

void CAVPDlg::MCT_SeedChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mMCT_HashSeedLenText->setText( QString("%1").arg(strLen));
}

void CAVPDlg::MCT_FirstMDChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mMCT_HashFirstMDLenText->setText( QString("%1").arg(strLen));
}

void CAVPDlg::MCT_LastMDChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mMCT_HashLastMDLenText->setText( QString("%1").arg(strLen));
}



void CAVPDlg::clickMCT_SymClear()
{
    mMCT_SymKeyText->clear();
    mMCT_SymIVText->clear();
    mMCT_SymPTText->clear();
    mMCT_SymCTText->clear();
    mMCT_SymLastKeyText->clear();
    mMCT_SymLastIVText->clear();
    mMCT_SymLastPTText->clear();
    mMCT_SymLastCTText->clear();
}

void CAVPDlg::clickMCT_HashClear()
{
    mMCT_HashSeedText->clear();
    mMCT_HashFirstMDText->clear();
    mMCT_HashLastMDText->clear();
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

int CAVPDlg::genRSAKeyPair( int nKeyLen, int nE, long *phPri, long *phPub )
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
    int nKeyType = CKK_RSA;

    CK_OBJECT_HANDLE hPubKey = -1;
    CK_OBJECT_HANDLE hPriKey = -1;

    char sPubLabel[128] = "GenRSAPubKey";
    char sPriLabel[128] = "GenRSAPriKey";

    CK_MECHANISM sMech;
    BIN binExp = {0,0};

    memset( &sMech, 0x00, sizeof(sMech));
    sMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

    hSession = mSessionText->text().toLong();

    /* Pub Template */
    sPubTemplate[nPubCount].type = CKA_CLASS;
    sPubTemplate[nPubCount].pValue = &pubClass;
    sPubTemplate[nPubCount].ulValueLen = sizeof(pubClass);
    nPubCount++;

    sPubTemplate[nPubCount].type = CKA_KEY_TYPE;
    sPubTemplate[nPubCount].pValue = &nKeyType;
    sPubTemplate[nPubCount].ulValueLen = sizeof(nKeyType);
    nPubCount++;

    sPubTemplate[nPubCount].type = CKA_MODULUS_BITS;
    sPubTemplate[nPubCount].pValue = &nKeyLen;
    sPubTemplate[nPubCount].ulValueLen = sizeof( nKeyLen );
    nPubCount++;

    JS_BIN_intToBin( nE, &binExp );
    sPubTemplate[nPubCount].type = CKA_PUBLIC_EXPONENT;
    sPubTemplate[nPubCount].pValue = binExp.pVal;
    sPubTemplate[nPubCount].ulValueLen = binExp.nLen;
    nPubCount++;

    if( bToken == true )
    {
        sPubTemplate[nPubCount].type = CKA_TOKEN;
        sPubTemplate[nPubCount].pValue = &kTrue;;
        sPubTemplate[nPubCount].ulValueLen = sizeof(CK_BBOOL);
        nPubCount++;
    }

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

    JS_BIN_reset( &binExp );

    return ret;
}

int CAVPDlg::importRSAPriKey( const BIN *pRSAPri, long *phPri )
{
    int ret = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();
    long uObj = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;

    JRSAKeyVal sRSAVal;

    BIN binN = {0,0};
    BIN binE = {0,0};
    BIN binD = {0,0};
    BIN binP = {0,0};
    BIN binQ = {0,0};
    BIN binDMP1 = {0,0};
    BIN binDMQ1 = {0,0};
    BIN binIQMP = {0,0};

    memset( &sRSAVal, 0x00, sizeof(sRSAVal));

    ret = JS_PKI_getRSAKeyVal( pRSAPri, &sRSAVal );
    if( ret != 0 ) goto end;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    sTemplate[uCount].type = CKA_SIGN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
    uCount++;

    if( sRSAVal.pN )
    {
        JS_BIN_decodeHex( sRSAVal.pN, &binN );
        sTemplate[uCount].type = CKA_MODULUS;
        sTemplate[uCount].pValue = binN.pVal;
        sTemplate[uCount].ulValueLen = binN.nLen;
        uCount++;
    }

    if( sRSAVal.pE )
    {
        JS_BIN_decodeHex( sRSAVal.pE, &binE );
        sTemplate[uCount].type = CKA_PUBLIC_EXPONENT;
        sTemplate[uCount].pValue = binE.pVal;
        sTemplate[uCount].ulValueLen = binE.nLen;
        uCount++;
    }

    if( sRSAVal.pD )
    {
        JS_BIN_decodeHex( sRSAVal.pD, &binD );
        sTemplate[uCount].type = CKA_PRIVATE_EXPONENT;
        sTemplate[uCount].pValue = binD.pVal;
        sTemplate[uCount].ulValueLen = binD.nLen;
        uCount++;
    }

    if( sRSAVal.pP )
    {
        JS_BIN_decodeHex( sRSAVal.pP, &binP );
        sTemplate[uCount].type = CKA_PRIME_1;
        sTemplate[uCount].pValue = binP.pVal;
        sTemplate[uCount].ulValueLen = binP.nLen;
        uCount++;
    }

    if( sRSAVal.pQ )
    {
        JS_BIN_decodeHex( sRSAVal.pQ, &binQ );
        sTemplate[uCount].type = CKA_PRIME_2;
        sTemplate[uCount].pValue = binQ.pVal;
        sTemplate[uCount].ulValueLen = binQ.nLen;
        uCount++;
    }

    if( sRSAVal.pDMP1 )
    {
        JS_BIN_decodeHex( sRSAVal.pDMP1, &binDMP1 );
        sTemplate[uCount].type = CKA_EXPONENT_1;
        sTemplate[uCount].pValue = binDMP1.pVal;
        sTemplate[uCount].ulValueLen = binDMP1.nLen;
        uCount++;
    }

    if( sRSAVal.pDMQ1 )
    {
        JS_BIN_decodeHex( sRSAVal.pDMQ1, &binDMQ1 );
        sTemplate[uCount].type = CKA_EXPONENT_2;
        sTemplate[uCount].pValue = binDMQ1.pVal;
        sTemplate[uCount].ulValueLen = binDMQ1.nLen;
        uCount++;
    }

    if( sRSAVal.pIQMP )
    {
        JS_BIN_decodeHex( sRSAVal.pIQMP, &binIQMP );
        sTemplate[uCount].type = CKA_COEFFICIENT;
        sTemplate[uCount].pValue = binIQMP.pVal;
        sTemplate[uCount].ulValueLen = binIQMP.nLen;
        uCount++;
    }

    ret = pAPI->CreateObject( hSession, sTemplate, uCount, (CK_ULONG_PTR)&uObj );
    if( ret == CKR_OK )
    {
        *phPri = uObj;
    }

end :
    JS_PKI_resetRSAKeyVal( &sRSAVal );
    JS_BIN_reset( &binN );
    JS_BIN_reset( &binE );
    JS_BIN_reset( &binD );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binDMP1 );
    JS_BIN_reset( &binDMQ1 );
    JS_BIN_reset( &binIQMP );

    return ret;
}

int CAVPDlg::importRSAPubKey( const BIN *pRSAPub, long *phPub )
{
    int ret = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();
    long uObj = -1;

    CK_ATTRIBUTE sTemplate[10];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;

    JRSAKeyVal sRSAVal;

    BIN binN = {0,0};
    BIN binE = {0,0};

    memset( &sRSAVal, 0x00, sizeof(sRSAVal));

    ret = JS_PKI_getRSAKeyValFromPub( pRSAPub, &sRSAVal );
    if( ret != 0 ) goto end;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    sTemplate[uCount].type = CKA_VERIFY;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
    uCount++;

    if( sRSAVal.pN )
    {
        JS_BIN_decodeHex( sRSAVal.pN, &binN );
        sTemplate[uCount].type = CKA_MODULUS;
        sTemplate[uCount].pValue = binN.pVal;
        sTemplate[uCount].ulValueLen = binN.nLen;
        uCount++;
    }

    if( sRSAVal.pE )
    {
        JS_BIN_decodeHex( sRSAVal.pE, &binE );
        sTemplate[uCount].type = CKA_PUBLIC_EXPONENT;
        sTemplate[uCount].pValue = binE.pVal;
        sTemplate[uCount].ulValueLen = binE.nLen;
        uCount++;
    }

    ret = pAPI->CreateObject( hSession, sTemplate, uCount, (CK_ULONG_PTR)&uObj );
    if( ret == CKR_OK )
    {
        *phPub = uObj;
    }

end :
    JS_PKI_resetRSAKeyVal( &sRSAVal );
    JS_BIN_reset( &binN );
    JS_BIN_reset( &binE );

    return ret;
}

int CAVPDlg::genECCKeyPair( const QString strParam, long *phPri, long *phPub )
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
    int nKeyType = CKK_EC;

    BIN binParam = {0,0};
    char sParamHex[256];

    memset( &sMech, 0x00, sizeof(sMech));
    memset( sParamHex, 0x00, sizeof(sParamHex));
    sMech.mechanism = CKM_ECDSA_KEY_PAIR_GEN;

    hSession = mSessionText->text().toLong();

    /* Pub Template */
    sPubTemplate[nPubCount].type = CKA_CLASS;
    sPubTemplate[nPubCount].pValue = &pubClass;
    sPubTemplate[nPubCount].ulValueLen = sizeof(pubClass);
    nPubCount++;

    sPubTemplate[nPubCount].type = CKA_KEY_TYPE;
    sPubTemplate[nPubCount].pValue = &nKeyType;
    sPubTemplate[nPubCount].ulValueLen = sizeof(nKeyType);
    nPubCount++;

    JS_PKI_getHexOIDFromSN( strParam.toStdString().c_str(), sParamHex );
    JS_BIN_decodeHex( sParamHex, &binParam );

    sPubTemplate[nPubCount].type = CKA_EC_PARAMS;
    sPubTemplate[nPubCount].pValue = binParam.pVal;
    sPubTemplate[nPubCount].ulValueLen = binParam.nLen;
    nPubCount++;

    if( bToken == true )
    {
        sPubTemplate[nPubCount].type = CKA_TOKEN;
        sPubTemplate[nPubCount].pValue = &kTrue;;
        sPubTemplate[nPubCount].ulValueLen = sizeof(CK_BBOOL);
        nPubCount++;
    }

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

    JS_BIN_reset( &binParam );
    return ret;
}

int CAVPDlg::importECCPriKey( const BIN *pECCPri, long *phPri )
{
    int ret = 0;
    CK_BBOOL bFalse = false;
    CK_BBOOL bTrue = true;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();
    long uObj = -1;

    CK_ATTRIBUTE sTemplate[10];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC;

    BIN binParam = {0,0};
    char sParamHex[256];
    BIN binValue = {0,0};

    JECKeyVal sECVal;

    memset( &sECVal, 0x00, sizeof(sECVal));
    memset( sParamHex, 0x00, sizeof(sParamHex));

    ret = JS_PKI_getECKeyVal( pECCPri, &sECVal );
    if( ret != 0 ) goto end;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    JS_PKI_getHexOIDFromSN( sECVal.pCurveOID, sParamHex );
    JS_BIN_decodeHex( sParamHex, &binParam );

    sTemplate[uCount].type = CKA_EC_PARAMS;
    sTemplate[uCount].pValue = binParam.pVal;
    sTemplate[uCount].ulValueLen = binParam.nLen;
    uCount++;


    JS_BIN_decodeHex( sECVal.pPrivate, &binValue );

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = binValue.pVal;
    sTemplate[uCount].ulValueLen = binValue.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_DERIVE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    ret = pAPI->CreateObject( hSession, sTemplate, uCount, (CK_OBJECT_HANDLE_PTR)&uObj );
    if( ret == CKR_OK )
    {
        *phPri = uObj;
    }


end :
    JS_PKI_resetECKeyVal( &sECVal );
    JS_BIN_reset( &binParam );
    JS_BIN_reset( &binValue );


    return ret;
}

int CAVPDlg::importECCPubKey( const BIN *pECCPub, long *phPub )
{
    int ret = 0;
    bool bToken = false;
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();
    long uObj = -1;

    CK_ATTRIBUTE sTemplate[10];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_EC;

    BIN binParam = {0,0};
    char sParamHex[256];

    JECKeyVal sECVal;

    BIN binECPoint={0,0};
    BIN binPubX = {0,0};
    BIN binPubY = {0,0};

    memset( &sECVal, 0x00, sizeof(sECVal));
    memset( sParamHex, 0x00, sizeof(sParamHex));

    ret = JS_PKI_getECKeyValFromPub( pECCPub, &sECVal );
    if( ret != 0 ) goto end;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    JS_PKI_getHexOIDFromSN( sECVal.pCurveOID, sParamHex );
    JS_BIN_decodeHex( sParamHex, &binParam );

    sTemplate[uCount].type = CKA_EC_PARAMS;
    sTemplate[uCount].pValue = binParam.pVal;
    sTemplate[uCount].ulValueLen = binParam.nLen;
    uCount++;


    unsigned char sPrefix[3];

    JS_BIN_decodeHex( sECVal.pPubX, &binPubX );
    JS_BIN_decodeHex( sECVal.pPubY, &binPubY );

    sPrefix[0] = 0x04;
    sPrefix[1] = binPubX.nLen + binPubY.nLen + 1;
    sPrefix[2] = 0x04;

    JS_BIN_set( &binECPoint, sPrefix, 3 );
    JS_BIN_appendBin( &binECPoint, &binPubX );
    JS_BIN_appendBin( &binECPoint, &binPubY );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );

    sTemplate[uCount].type = CKA_EC_POINT;
    sTemplate[uCount].pValue = binECPoint.pVal;
    sTemplate[uCount].ulValueLen = binECPoint.nLen;
    uCount++;

    ret = pAPI->CreateObject( hSession, sTemplate, uCount, (CK_ULONG_PTR)&uObj );
    if( ret == CKR_OK )
    {
        *phPub = uObj;
    }

end :
    JS_PKI_resetECKeyVal( &sECVal );
    JS_BIN_reset( &binParam );
    JS_BIN_reset( &binECPoint );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );

    return ret;
}

int CAVPDlg::deriveKeyECDH( long uPri, const BIN *pPubX, const BIN *pPubY, long* phObj )
{
    int ret = 0;

    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();
    long uObj = -1;

    CK_ATTRIBUTE sTemplate[10];
    long uCount = 0;

    CK_MECHANISM sMech;
    CK_ECDH1_DERIVE_PARAMS_PTR pParam = NULL;
    pParam = (CK_ECDH1_DERIVE_PARAMS *)JS_calloc( 1, sizeof(CK_ECDH1_DERIVE_PARAMS));

    BIN binPub = {0,0};

    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;

    CK_ULONG uKeyLen = 16;
    char sLabel[16] = "DeriveKey";

    memset( &sMech, 0x00, sizeof(sMech));

    JS_BIN_setChar( &binPub, 0x04, 1 );
    JS_BIN_appendBin( &binPub, pPubX );
    JS_BIN_appendBin( &binPub, pPubY );

    pParam->kdf = CKD_NULL;
    pParam->pPublicData = binPub.pVal;
    pParam->ulPublicDataLen = binPub.nLen;
    pParam->pSharedData = NULL;
    pParam->ulSharedDataLen = 0;

    sMech.mechanism = CKM_ECDH1_DERIVE;
    sMech.pParameter = pParam;
    sMech.ulParameterLen = sizeof(CK_ECDH1_DERIVE_PARAMS);

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_LABEL;
    sTemplate[uCount].pValue = sLabel;
    sTemplate[uCount].ulValueLen = sizeof(sLabel);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    sTemplate[uCount].type = CKA_VALUE_LEN;
    sTemplate[uCount].pValue = &uKeyLen;
    sTemplate[uCount].ulValueLen = sizeof(uKeyLen);
    uCount++;

    sTemplate[uCount].type = CKA_SENSITIVE;
    sTemplate[uCount].pValue = &bFalse;
    sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
    uCount++;

    sTemplate[uCount].type = CKA_EXTRACTABLE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
    uCount++;

    ret = pAPI->DeriveKey( hSession, &sMech, uPri, sTemplate, uCount, (CK_OBJECT_HANDLE_PTR)&uObj );
    if( ret == CKR_OK )
    {
        *phObj = uObj;
    }

end :
    JS_BIN_reset( &binPub );
    if( pParam ) JS_free( pParam );

    return ret;
}

int CAVPDlg::makeSymData( const QString strAlgMode, const BIN *pKey, const BIN *pIV, const BIN *pPT )
{
    int ret = 0;
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    BIN binEnc = {0,0};

    QStringList list = strAlgMode.split( "-" );
    if( list.size() < 2 ) return -1;

    long hKey = -1;
    QString strAlg = list.at(0);
    QString strMode = list.at(1);

    int nKeyAlg = _getCKK( strAlg );
    CK_MECHANISM sMech;

    long uOutLen = 0;
    unsigned char *pOut = NULL;

    memset( &sMech, 0x00, sizeof(sMech));

    sMech.mechanism = _getCKM_Cipher( strAlg, strMode );
    sMech.pParameter = pIV->pVal;
    sMech.ulParameterLen = pIV->nLen;

    ret = createKey( nKeyAlg, pKey, &hKey );
    if( ret != 0 ) goto end;

    ret = pAPI->EncryptInit( hSession, &sMech, hKey );
    if( ret != 0 ) goto end;

    ret = pAPI->Encrypt( hSession, pPT->pVal, pPT->nLen, NULL, (CK_ULONG_PTR)&uOutLen );
    if( ret != 0 ) goto end;
    pOut = (unsigned char *)JS_calloc( 1, uOutLen );

    ret = pAPI->Encrypt( hSession, pPT->pVal, pPT->nLen, pOut, (CK_ULONG_PTR)&uOutLen );
    if( ret != 0 ) goto end;

    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to encrypt [%1]").arg(ret));
        goto end;
    }

    JS_BIN_set( &binEnc, pOut, uOutLen );

    logRsp( QString( "CT = %1").arg( getHexString(binEnc.pVal, binEnc.nLen)));
    logRsp( "" );

end :
    if( pOut ) JS_free( pOut );
    JS_BIN_reset( &binEnc );

    return ret;
}

int CAVPDlg::makeAEData( const BIN *pKey, const BIN *pIV, const BIN *pPT, const BIN *pAAD, int nTagLen, int nSrcLen )
{
    int ret = 0;

    BIN binTag = {0,0};
    BIN binEnc = {0,0};

    QString strMode = mAEModeCombo->currentText();
    QString strAlg = mAEAlgCombo->currentText();
    QString strEncAlg;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();


    long uOutLen = 0;
    unsigned char *pOut = NULL;
    long hKey = -1;
    int nKeyAlg = _getCKK( strAlg );

    CK_MECHANISM sMech;
    memset( &sMech, 0x00, sizeof(sMech));

    logRsp( QString( "Key = %1").arg( getHexString( pKey ) ));
    logRsp( QString( "IV = %1").arg( getHexString( pIV )));
    logRsp( QString( "PT = %1").arg( getHexString( pPT )));
    logRsp( QString( "Adata = %1").arg( getHexString( pAAD )));

    sMech.mechanism = _getCKM_Cipher( strAlg, strMode );

    if( sMech.mechanism == CKM_AES_GCM )
    {
        setAES_GCMParam( pIV, pAAD, nTagLen, &sMech );
    }
    else if( sMech.mechanism == CKM_AES_GCM )
    {
        setAES_CCMParam( pIV, pAAD, nSrcLen, nTagLen, &sMech );
    }
    else
    {
        sMech.pParameter = pIV->pVal;
        sMech.ulParameterLen = pIV->nLen;
    }

    ret = createKey( nKeyAlg, pKey, &hKey );
    if( ret != 0 ) goto end;

    ret = pAPI->EncryptInit( hSession, &sMech, hKey );
    if( ret != 0 ) goto end;

    if( pPT->nLen > 0 )
    {
        ret = pAPI->Encrypt( hSession, pPT->pVal, pPT->nLen, NULL, (CK_ULONG_PTR)&uOutLen );
        if( ret != 0 ) goto end;
        pOut = (unsigned char *)JS_calloc( 1, uOutLen );

        ret = pAPI->Encrypt( hSession, pPT->pVal, pPT->nLen, pOut, (CK_ULONG_PTR)&uOutLen );
        if( ret != 0 ) goto end;

        JS_BIN_set( &binEnc, pOut, uOutLen - nTagLen );
        JS_BIN_set( &binTag, &pOut[uOutLen - nTagLen], nTagLen );
    }
    else
    {
        unsigned char sTag[128];
        int nTagLen = sizeof(sTag);

        memset( sTag, 0x00, sizeof(sTag));
        ret = pAPI->EncryptFinal( hSession, sTag, (CK_ULONG_PTR)&nTagLen );
        if( ret != 0 ) goto end;

        JS_BIN_set( &binTag, sTag, nTagLen );
    }



    logRsp( QString( "C = %1").arg(getHexString( binEnc.pVal, binEnc.nLen)));
    logRsp( QString( "T = %1").arg(getHexString( binTag.pVal, binTag.nLen)));
    logRsp( "" );

end :
    if( sMech.mechanism == CKM_AES_GCM || sMech.mechanism == CKM_AES_CCM )
    {
        if( sMech.pParameter ) JS_free( sMech.pParameter );
    }

    if( pOut ) JS_free( pOut );
    JS_BIN_reset( &binTag );
    JS_BIN_reset( &binEnc );

    return ret;
}

int CAVPDlg::makeADData( const BIN *pKey, const BIN *pIV, const BIN *pCT, const BIN *pAAD, const BIN *pTag, int nSrcLen )
{
    int ret = 0;

    BIN binPT = {0,0};

    QString strMode = mAEModeCombo->currentText();
    QString strAlg = mAEAlgCombo->currentText();
    QString strEncAlg;

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();


    long uOutLen = 0;
    unsigned char *pOut = NULL;
    long hKey = -1;
    int nKeyAlg = _getCKK( strAlg );

    BIN binSrc = {0,0};

    CK_MECHANISM sMech;
    memset( &sMech, 0x00, sizeof(sMech));

    logRsp( QString( "Key = %1").arg( getHexString( pKey ) ));
    logRsp( QString( "IV = %1").arg( getHexString( pIV )));
    logRsp( QString( "CT = %1").arg( getHexString( pCT )));
    logRsp( QString( "T = %1").arg( getHexString( pTag )));
    logRsp( QString( "Adata = %1").arg( getHexString( pAAD )));

    sMech.mechanism = _getCKM_Cipher( strAlg, strMode );

    if( sMech.mechanism == CKM_AES_GCM )
    {
        setAES_GCMParam( pIV, pAAD, pTag->nLen, &sMech );
    }
    else if( sMech.mechanism == CKM_AES_GCM )
    {
        setAES_CCMParam( pIV, pAAD, nSrcLen, pTag->nLen, &sMech );
    }
    else
    {
        sMech.pParameter = pIV->pVal;
        sMech.ulParameterLen = pIV->nLen;
    }

    ret = createKey( nKeyAlg, pKey, &hKey );
    if( ret != 0 ) goto err;

    ret = pAPI->DecryptInit( hSession, &sMech, hKey );
    if( ret != 0 ) goto err;

    JS_BIN_copy( &binSrc, pCT );
    JS_BIN_appendBin( &binSrc, pTag );

    ret = pAPI->Decrypt( hSession, binSrc.pVal, binSrc.nLen, NULL, (CK_ULONG_PTR)&uOutLen );
    if( ret != 0 ) goto end;
    pOut = (unsigned char *)JS_calloc( 1, uOutLen );

    ret = pAPI->Decrypt( hSession, binSrc.pVal, binSrc.nLen, pOut, (CK_ULONG_PTR)&uOutLen );
    if( ret != 0 ) goto end;

    JS_BIN_set( &binPT, pOut, uOutLen );

 end :
    if( ret == 0 )
    {
        logRsp( QString( "PT = %1").arg( getHexString(binPT.pVal, binPT.nLen)));
    }
    else
    {
        logRsp( "Invalid" );
        ret = 0;
    }

    logRsp( "" );
err:
    if( sMech.mechanism == CKM_AES_GCM || sMech.mechanism == CKM_AES_CCM )
    {
        if( sMech.pParameter ) JS_free( sMech.pParameter );
    }

    if( pOut ) JS_free( pOut );
    JS_BIN_reset( &binPT );
    JS_BIN_reset( &binSrc );

    return ret;
}

int CAVPDlg::makeHashData( int nLen, const BIN *pVal )
{
    int ret = 0;
    BIN binHash = {0,0};

    QString strAlg = mHashAlgCombo->currentText();

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;
    memset( &sMech, 0x00, sizeof(sMech));

    sMech.mechanism = _getCKM_Hash( strAlg );

    ret = pAPI->DigestInit( hSession, &sMech );
    if( ret != 0 ) goto end;

    nOutLen = sizeof(sOut);
    memset( sOut, 0x00, nOutLen );

    ret = pAPI->Digest( hSession, pVal->pVal, pVal->nLen, sOut, (CK_ULONG_PTR)&nOutLen );
    JS_BIN_set( &binHash, sOut, nOutLen );

    if( ret != 0 ) goto end;

    logRsp( QString( "Len = %1").arg( nLen ));
    logRsp( QString( "Msg = %1").arg( getHexString( pVal ) ));
    logRsp( QString( "MD = %1").arg(getHexString( binHash.pVal, binHash.nLen)));
    logRsp( "" );

end :
    JS_BIN_reset( &binHash );

    return ret;
}

int CAVPDlg::makeHMACData( const QString strCount, const QString strKLen, const QString strTLen, const BIN *pKey, const BIN *pMsg )
{
    int ret = 0;

    QString strAlg = mHashAlgCombo->currentText();

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 0;

    CK_MECHANISM sMech;
    memset( &sMech, 0x00, sizeof(sMech));

    BIN binMAC = {0,0};
    int nKeyType = CKK_GENERIC_SECRET;
    long uObj = -1;


    logRsp( QString( "Count = %1").arg( strCount ));
    logRsp( QString( "Klen = %1").arg( strKLen ));
    logRsp( QString( "Tlen = %1").arg(strTLen));
    logRsp( QString( "Key = %1").arg( getHexString( pKey ) ));
    logRsp( QString( "Msg = %1").arg( getHexString( pMsg ) ));


    ret = createKey( nKeyType, pKey, &uObj );
    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to create key: %1").arg(ret) );
        goto end;
    }

    sMech.mechanism = _getCKM_HMAC( strAlg );

    ret = pAPI->SignInit( hSession, &sMech, uObj );
    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to sign init ret:%1").arg(ret));
        goto end;
    }

    nOutLen = sizeof(sOut);
    ret = pAPI->Sign( hSession, pMsg->pVal, pMsg->nLen, sOut, (CK_ULONG_PTR)&nOutLen );
    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to sign ret:%1").arg(ret));
        goto end;
    }

    logRsp( QString( "Mac = %1").arg(getHexString(sOut, strTLen.toInt())));
    logRsp( "" );

end :
    JS_BIN_reset( &binMAC );

    return ret;
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

            repaint();
        }

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

            repaint();
        }

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

            repaint();
        }

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

            repaint();
        }

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

            repaint();
        }


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

            repaint();
        }

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

            repaint();
        }

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

            repaint();
        }

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

            repaint();
        }


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

            repaint();
        }

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
            repaint();
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
            repaint();
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

    case kACVP_TYPE_KDA :
        ret = kdaJsonWork( strAlg, jObject, jRspObject );
        break;
/*
    case kACVP_TYPE_DSA:
        ret = dsaJsonWork( strMode, jObject, jRspObject );
        break;
*/
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
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    QString strMctVersion = jObject["mctVersion"].toString();

    int nTgId = jObject["tgId"].toInt();
    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    BIN binMsg = {0,0};
    BIN binMD = {0,0};

    QString strHash = _getHashName( strAlg );

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 1024;

    CK_MECHANISM sMech;
    memset( &sMech, 0x00, sizeof(sMech));

    if( strHash.length() < 1 )
    {
        manApplet->warningBox( QString("Invalid algorithm: %1").arg( strAlg ), this );
        return -1;
    }

    sMech.mechanism = _getCKM_Hash( strHash );

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();
        QString strMsg = jObj["msg"].toString();

        QJsonObject jRspTestObj;

        jRspTestObj["tcId"] = nTcId;

        JS_BIN_reset( &binMD );
        JS_BIN_reset( &binMsg );

        if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "LDT" )
        {
            void *pCTX = NULL;
            QJsonObject jLDTObj = jObj["largeMsg"].toObject();
            QString strContent = jLDTObj["content"].toString();
            int nContentLength = jLDTObj["contentLength"].toInt();
            QString strExpansionTechnique = jLDTObj["repeating"].toString();
            qint64 nFullLength = jLDTObj["fullLength"].toDouble();

            qint64 nFullBytes = nFullLength / 8;
            qint64 nLeft = nFullBytes;

            BIN binData = {0,0};
            BIN binMD = {0,0};

            JS_BIN_decodeHex( strContent.toStdString().c_str(), &binData );

            ret = pAPI->DigestInit( hSession, &sMech );

            if( ret != 0 )
            {
                JS_BIN_reset( &binData );
                goto end;
            }

            while( nLeft > 0 )
            {
 //               ret = JS_PKI_hashUpdate( pCTX, &binData );
                ret = pAPI->DigestUpdate( hSession, binData.pVal, binData.nLen );
                if( ret != 0 )
                {
                    JS_BIN_reset( &binData );
                    goto end;
                }

                nLeft -= binData.nLen;
            }


            ret = pAPI->DigestFinal( hSession, sOut, (CK_ULONG_PTR)&nOutLen );

            if( ret == 0 ) jRspObject["md"] = getHexString( sOut, nOutLen );

            JS_BIN_reset( &binData );
        }
        else if( strTestType == "MCT" )
        {
            QJsonArray jMDArr;
            BIN binSeed = {0,0};
            JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binSeed );

            if( strMctVersion == "alternate" )
            {
                ret = makeHash_AlternateMCT( strAlg, &binSeed, jMDArr );
            }
            else
            {
                ret = makeHash_MCT( strAlg, &binSeed, jMDArr );
            }

            JS_BIN_reset( &binSeed );
            if( ret != 0 ) goto end;

            jRspTestObj["resultsArray"] = jMDArr;
        }
        else
        {
            nOutLen = sizeof(sOut);

            ret = pAPI->DigestInit( hSession, &sMech );
            if( ret != 0 ) goto end;

            if( binMsg.nLen > 0 )
            {
                ret = pAPI->DigestUpdate( hSession, binMsg.pVal, binMsg.nLen );
                if( ret != 0 ) goto end;
            }

            ret = pAPI->DigestFinal( hSession, sOut, (CK_ULONG_PTR)&nOutLen );
            if( ret != 0 ) goto end;

            jRspTestObj["md"] = getHexString( sOut, nOutLen );
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binMD );

    return ret;
}

int CAVPDlg::ecdsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;

    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    QString strCurve = jObject["curve"].toString();
    QString strHashAlg = jObject["hashAlg"].toString();
    QString strConformance = jObject["conformance"].toString();
    QString strSecretGerenationMode = jObject["secretGenerationMode"].toString();

    BIN binPub = {0,0};
    BIN binPri = {0,0};
    BIN binMsg = {0,0};
    BIN binSign = {0,0};

    BIN binR = {0,0};
    BIN binS = {0,0};

    BIN binQX = {0,0};
    BIN binQY = {0,0};

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    QString strUseHash = _getHashName( strHashAlg );
    QString strUseCurve = _getECCurveName( strCurve );

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 1024;

    long uPri = -1;
    long uPub = -1;

    CK_MECHANISM sMech;
    memset( &sMech, 0x00, sizeof(sMech));

    if( strMode == "sigGen" )
    {
        JECKeyVal sECKeyVal;

        memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

        ret = genECCKeyPair( strUseCurve, &uPri, &uPub );
        if( ret != 0 ) goto end;

        ret = pAPI->getECCKeyVal( hSession, uPub, &sECKeyVal );
        if( ret != 0 ) goto end;

        jRspObject["qx"] = sECKeyVal.pPubX;
        jRspObject["qy"] = sECKeyVal.pPubY;

        JS_PKI_resetECKeyVal( &sECKeyVal );
    }

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();
        QString strMsg = jObj["message"].toString();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        QString strQX = jObj["qx"].toString();
        QString strQY = jObj["qy"].toString();

        QString strR = jObj["r"].toString();
        QString strS = jObj["s"].toString();

        JS_BIN_reset( &binSign );
        JS_BIN_reset( &binMsg );
        JS_BIN_reset( &binR );
        JS_BIN_reset( &binS );
        JS_BIN_reset( &binQX );
        JS_BIN_reset( &binQY );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "AFT" )
        {
            if( strMode == "keyGen" )
            {
                JECKeyVal sPriVal;
                JECKeyVal sPubVal;

                memset( &sPriVal, 0x00, sizeof(sPriVal));
                memset( &sPubVal, 0x00, sizeof(sPubVal));

                uPri = -1;
                uPub = -1;

                ret = genECCKeyPair( strUseCurve, &uPri, &uPub );
                if( ret != 0 ) goto end;

                ret = pAPI->getECCKeyVal( hSession, uPri, &sPriVal );
                if( ret != 0 ) goto end;

                ret = pAPI->getECCKeyVal( hSession, uPub, &sPubVal );
                if( ret != 0 ) goto end;

                jRspTestObj["d"] = sPriVal.pPrivate;
                jRspTestObj["qx"] = sPubVal.pPubX;
                jRspTestObj["qy"] = sPubVal.pPubY;

                JS_PKI_resetECKeyVal( &sPriVal );
                JS_PKI_resetECKeyVal( &sPubVal );
                if( uPri > 0 ) pAPI->DestroyObject( hSession, uPri );
                if( uPub > 0 ) pAPI->DestroyObject( hSession, uPub );
            }
            else if( strMode == "keyVer" )
            {
                bool bRes = false;
                JECKeyVal sECVal;

                memset( &sECVal, 0x00, sizeof(sECVal));

                JS_BIN_decodeHex( strQX.toStdString().c_str(), &binQX );
                JS_BIN_decodeHex( strQY.toStdString().c_str(), &binQY );

                ret = JS_PKI_IsValidECCPubKey( strUseCurve.toStdString().c_str(), &binQX, &binQY );
                if( ret == JSR_VALID )
                    bRes = true;
                else
                    bRes = false;

                JS_PKI_setECKeyVal( &sECVal,
                                   strUseCurve.toStdString().c_str(),
                                   strQX.toStdString().c_str(),
                                   strQY.toStdString().c_str(),
                                   NULL );

                ret = JS_PKI_encodeECPublicKey( &sECVal, &binPub );
                if( ret != 0 )
                {
                    bRes = false;
                }

                ret = importECCPubKey( &binPub, &uPub );
                if( ret != 0 )
                {
                    bRes = false;
                }
                else
                    bRes = true;

                jRspTestObj["testPassed"] = bRes;
                JS_PKI_resetECKeyVal( &sECVal );

                ret = 0;
            }
            else if( strMode == "sigGen" )
            {
                if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );

                ret = JS_PKI_ECCMakeSign( strUseHash.toStdString().c_str(), &binMsg, &binPri, &binSign );
                if( ret != 0 ) goto end;

                ret = JS_PKI_decodeECCSign( &binSign, &binR, &binS );
                if( ret != 0 ) goto end;

                uPri = -1;
                ret = importECCPriKey( &binPri, &uPri );
                if( ret != 0 ) goto end;

                nOutLen = sizeof(sOut);

                sMech.mechanism = _getCKM_ECDSA( strUseHash );

                ret = pAPI->SignInit( hSession, &sMech, uPri );
                if( ret != 0 ) goto end;

                ret = pAPI->Sign( hSession, binMsg.pVal, binMsg.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                if( ret != 0 ) goto end;

                JS_BIN_set( &binSign, sOut, nOutLen );
                JS_PKI_decodeECCSign( &binSign, &binR, &binS );

                jRspTestObj["r"] = getHexString( &binR );
                jRspTestObj["s"] = getHexString( &binS );

                if( uPri > 0 ) pAPI->DestroyObject( hSession, uPri );
            }
            else if( strMode == "sigVer" )
            {
                bool bRes = false;

                if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );
                if( strR.length() > 0 ) JS_BIN_decodeHex( strR.toStdString().c_str(), &binR );
                if( strS.length() > 0 ) JS_BIN_decodeHex( strS.toStdString().c_str(), &binS );

                JECKeyVal sECKeyVal;

                char sOID[1024];

                memset( sOID, 0x00, sizeof(sOID));

                memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));
                JS_PKI_getOIDFromSN( strUseCurve.toStdString().c_str(), sOID );

                sECKeyVal.pCurveOID = sOID;
                sECKeyVal.pPubX = (char *)strQX.toStdString().c_str();
                sECKeyVal.pPubY = (char *)strQY.toStdString().c_str();
                JS_BIN_reset( &binPub );

                ret = JS_PKI_encodeECPublicKey( &sECKeyVal, &binPub );
                if( ret != 0 ) goto end;

                // Need to make sign
                ret = JS_PKI_encodeECCSign( &binR, &binS, &binSign );
                if( ret != 0 ) goto end;

                ret = JS_PKI_ECCVerifySign( strUseHash.toStdString().c_str(), &binMsg, &binSign, &binPub );

                nOutLen = sizeof(sOut);

                sMech.mechanism = _getCKM_ECDSA( strUseHash );

                uPub = -1;
                ret = importECCPubKey( &binPub, &uPub );
                if( ret != 0 ) bRes = false;

                ret = pAPI->VerifyInit( hSession, &sMech, uPub );
                if( ret != 0 ) bRes = false;

                ret = pAPI->Verify( hSession, binMsg.pVal, binMsg.nLen, binSign.pVal, binSign.nLen );
                if( ret == 0 ) bRes = true;

                if( ret == JSR_VERIFY )
                    bRes = true;
                else
                    bRes = false;

                jRspTestObj["testPassed"] = bRes;
                if( uPub > 0 ) pAPI->DestroyObject( hSession, uPub );

                ret = 0;
            }
            else
            {
                manApplet->warnLog( tr("Invalid Mode: %1").arg( strMode ), this );
                ret = -1;
                goto end;
            }
        }
        else
        {
            manApplet->warnLog( tr("Invalid test type: %1").arg( strTestType), this );
            ret = -1;
            goto end;
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binSign );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binS );
    JS_BIN_reset( &binQX );
    JS_BIN_reset( &binQY );

    return ret;
}



int CAVPDlg::rsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    int nModulo = jObject["modulo"].toInt();

    BIN binPub = {0,0};
    BIN binPri = {0,0};
    BIN binSign = {0,0};
    BIN binMsg = {0,0};
    BIN binE = {0,0};

    //KeyGen
    bool bInfoGeneratedByServer = jObject["infoGeneratedByServer"].toBool();
    QString strKeyFormat = jObject["keyFormat"].toString();

    QString strPrimeTest = jObject["primeTest"].toString();
    QString strPubExp = jObject["pubExp"].toString();
    QString strRandPQ = jObject["randPQ"].toString();
    QString strFixedPubExp = jObject["fixedPubExp"].toString();

    //SigGen or SigVer
    QString strHashAlg = jObject["hashAlg"].toString();
    QString strMaskFunction = jObject["maskFunction"].toString();
    int nSaltLen = jObject["saltLen"].toInt();
    QString strSigType = jObject["sigType"].toString();

    QString strE = jObject["e"].toString();
    QString strN = jObject["n"].toString();

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    QString strUseHash = _getHashName( strHashAlg );

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 1024;

    long uPri = -1;
    long uPub = -1;

    CK_MECHANISM sMech;
    memset( &sMech, 0x00, sizeof(sMech));

    if( strMode == "sigGen" )
    {
        int nExponent = 65537;
        JRSAKeyVal sRSAKeyVal;

        memset( &sRSAKeyVal, 0x00, sizeof(sRSAKeyVal));

        ret = genRSAKeyPair( nModulo, nExponent, &uPri, &uPub );
        if( ret != 0 ) goto end;

        ret = pAPI->getRSAKeyVal( hSession, uPri, &sRSAKeyVal );
        if( ret != 0 ) goto end;

        jRspObject["e"] = sRSAKeyVal.pE;
        jRspObject["n"] = sRSAKeyVal.pN;

        JS_PKI_resetRSAKeyVal( &sRSAKeyVal );
    }
    else if( strMode == "sigVer" )
    {
        JRSAKeyVal sRSAKeyVal;

        memset( &sRSAKeyVal, 0x00, sizeof(sRSAKeyVal));

        sRSAKeyVal.pE = (char *)strE.toStdString().c_str();
        sRSAKeyVal.pN = (char *)strN.toStdString().c_str();

        ret = JS_PKI_encodeRSAPublicKey( &sRSAKeyVal, &binPub );
        if( ret != 0 ) goto end;

        ret = importRSAPubKey( &binPub, &uPub );
        if( ret != 0 ) goto end;
    }

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();

        bool bDeferred = jObj["deferred"].toBool();
        QString strMsg = jObj["message"].toString();
        QString strSign = jObj["signature"].toString();
        QString strValE = jObj["e"].toString();
        QString strValP = jObj["p"].toString();
        QString strValQ = jObj["q"].toString();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "GDT" )
        {
            if( strMode == "keyGen" )
            {
                int nExponent = 0;
                JRSAKeyVal sRSAKey;

                JS_BIN_reset( &binPri );
                JS_BIN_reset( &binPub );

                JS_BIN_reset( &binE );
                JS_BIN_decodeHex( strFixedPubExp.toStdString().c_str(), &binE );

                nExponent = JS_BIN_int( &binE );

                memset( &sRSAKey, 0x00, sizeof(sRSAKey));

                ret = genRSAKeyPair( nModulo, nExponent, &uPri, &uPub );
                if( ret != 0 ) goto end;

                ret = pAPI->getRSAKeyVal( hSession, uPri, &sRSAKey );
                if( ret != 0 ) goto end;

                jRspTestObj["d"] = sRSAKey.pD;
                jRspTestObj["e"] = sRSAKey.pE;
                jRspTestObj["n"] = sRSAKey.pN;
                jRspTestObj["p"] = sRSAKey.pP;
                jRspTestObj["q"] = sRSAKey.pQ;

                JS_PKI_resetRSAKeyVal( &sRSAKey );

                if( uPri > 0 ) pAPI->DestroyObject( hSession, uPri );
                if( uPub > 0 ) pAPI->DestroyObject( hSession, uPub );
            }
            else if( strMode == "sigGen" )
            {
                int nVersion = JS_PKI_RSA_PADDING_V15;

                if( strSigType == "pss" )
                {
                    nVersion = JS_PKI_RSA_PADDING_V21;
                    sMech.mechanism = _getCKM_RSA( strUseHash, true );
                }
                else
                {
                    sMech.mechanism = _getCKM_RSA( strUseHash, false );
                }

                JS_BIN_reset( &binMsg );
                JS_BIN_reset( &binSign );

                if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );

                ret = importRSAPriKey( &binPri, &uPri );
                if( ret != 0 ) goto end;

                nOutLen = sizeof(sOut );

                ret = pAPI->SignInit( hSession, &sMech, uPri );
                if( ret != 0 ) goto end;

                ret = pAPI->Sign( hSession, binMsg.pVal, binMsg.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                if( ret != 0 ) goto end;

                JS_BIN_set( &binSign, sOut, nOutLen );

                jRspTestObj["signature"] = getHexString( &binSign );
                if( uPri > 0 ) pAPI->DestroyObject( hSession, uPri );
            }
            else if( strMode == "sigVer" )
            {
                bool bRes = false;

                int nVersion = JS_PKI_RSA_PADDING_V15;

                if( strSigType == "pss" )
                {
                    nVersion = JS_PKI_RSA_PADDING_V21;
                    sMech.mechanism = _getCKM_RSA( strUseHash, true );
                }
                else
                {
                    sMech.mechanism = _getCKM_RSA( strUseHash, false );
                }

                JS_BIN_reset( &binMsg );
                JS_BIN_reset( &binSign );

                if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );
                if( strSign.length() > 0 ) JS_BIN_decodeHex( strSign.toStdString().c_str(), &binSign );

                ret = importRSAPubKey( &binPub, &uPub );
                if( ret != 0 ) goto end;

                ret = pAPI->VerifyInit( hSession, &sMech, uPub );
                if( ret != 0 ) goto end;

                ret = pAPI->Verify( hSession, binMsg.pVal, binMsg.nLen, binSign.pVal, binSign.nLen );
                if( ret != 0 )
                {
                    bRes = false;
                }
                else
                {
                    bRes = true;
                }

                jRspTestObj["testPassed"] = bRes;
                if( uPub > 0 ) pAPI->DestroyObject( hSession, uPub );

                ret = 0;
            }
            else
            {
                manApplet->warnLog( tr("Invalid Mode: %1").arg( strMode ), this );
                ret = -1;
                goto end;
            }
        }
        else
        {
            manApplet->warnLog( tr("Invalid test type: %1").arg( strTestType), this );
            ret = -1;
            goto end;
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binSign );
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binE );

    if( uPri > 0 ) pAPI->DestroyObject( hSession, uPri );
    if( uPub > 0 ) pAPI->DestroyObject( hSession, uPub );

    return ret;
}

/*
int CAVPDlg::dsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    int nL = jObject["l"].toInt();
    int nN = jObject["n"].toInt();
    QString strHashAlg = jObject["hashAlg"].toString();
    QString strG = jObject["g"].toString();
    QString strP = jObject["p"].toString();
    QString strQ = jObject["q"].toString();

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    BIN binG = {0,0};
    BIN binP = {0,0};
    BIN binQ = {0,0};

    BIN binMsg = {0,0};
    BIN binSign = {0,0};
    BIN binR = {0,0};
    BIN binS = {0,0};
    BIN binY = {0,0};

    BIN binParam = {0,0};
    BIN binPub = {0,0};
    BIN binPri = {0,0};

    QString strUseHash = _getHashName( strHashAlg );

    if( strMode == "keyGen" || strMode == "sigGen" )
    {
        ret = JS_PKI_DSA_GenParam( nL, &binParam );
        if( ret != 0 ) goto end;

        ret = JS_PKI_DSA_GetParamValue( &binParam, &binP, &binQ, &binG );
        if( ret != 0 ) goto end;

        jRspObject["g"] = getHexString( &binG );
        jRspObject["p"] = getHexString( &binP );
        jRspObject["q"] = getHexString( &binQ );

        if( strMode == "sigGen" )
        {
            JDSAKeyVal sDSAKey;

            memset( &sDSAKey, 0x00, sizeof(sDSAKey));

            ret = JS_PKI_DSA_GenKeyPairWithParam( &binParam, &binPub, &binPri );
            if( ret != 0 ) goto end;

            ret = JS_PKI_getDSAKeyVal( &binPri, &sDSAKey );
            if( ret != 0 ) goto end;

            jRspObject["y"] = sDSAKey.pPublic;

            JS_PKI_resetDSAKeyVal( &sDSAKey );
        }
    }
    else if( strMode == "sigVer" )
    {
        JS_BIN_decodeHex( strG.toStdString().c_str(), &binG );
        JS_BIN_decodeHex( strP.toStdString().c_str(), &binP );
        JS_BIN_decodeHex( strQ.toStdString().c_str(), &binQ );
    }

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        QString strMsg = jObj["message"].toString();
        QString strR = jObj["r"].toString();
        QString strS = jObj["s"].toString();
        QString strY = jObj["y"].toString();

        JS_BIN_reset( &binMsg );
        JS_BIN_reset( &binR );
        JS_BIN_reset( &binS );
        JS_BIN_reset( &binY );

        if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );
        if( strR.length() > 0 ) JS_BIN_decodeHex( strR.toStdString().c_str(), &binR );
        if( strS.length() > 0 ) JS_BIN_decodeHex( strS.toStdString().c_str(), &binS );
        if( strY.length() > 0 ) JS_BIN_decodeHex( strY.toStdString().c_str(), &binY );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "AFT" )
        {
            if( strMode == "keyGen" )
            {
                JDSAKeyVal sDSAKey;

                JS_BIN_reset( &binPub );
                JS_BIN_reset( &binPri );

                memset( &sDSAKey, 0x00, sizeof(sDSAKey));

                ret = JS_PKI_DSA_GenKeyPairWithParam( &binParam, &binPub, &binPri );
                if( ret != 0 ) goto end;

                ret = JS_PKI_getDSAKeyVal( &binPri, &sDSAKey );
                if( ret != 0 ) goto end;

                jRspTestObj["x"] = sDSAKey.pPrivate;
                jRspTestObj["y"] = sDSAKey.pPublic;

                JS_PKI_resetDSAKeyVal( &sDSAKey );
            }
            else if( strMode == "sigGen" )
            {
                JS_BIN_reset( &binSign );
                JS_BIN_reset( &binR );
                JS_BIN_reset( &binS );

                ret = JS_PKI_DSA_Sign( strUseHash.toStdString().c_str(), &binMsg, &binPri, &binSign );
                if( ret != 0 ) goto end;

                ret = JS_PKI_DSA_decodeSign( &binSign, &binR, &binS );
                if( ret != 0 ) goto end;

                jRspTestObj["r"] = getHexString( &binR );
                jRspTestObj["s"] = getHexString( &binS );
            }
            else if( strMode == "sigVer" )
            {
                bool bRes = false;
                JDSAKeyVal sDSAKey;

                memset( &sDSAKey, 0x00, sizeof(sDSAKey));

                JS_BIN_reset( &binSign );
                JS_BIN_reset( &binPub );

                sDSAKey.pG = (char *)strG.toStdString().c_str();
                sDSAKey.pP = (char *)strP.toStdString().c_str();
                sDSAKey.pQ = (char *)strQ.toStdString().c_str();
                sDSAKey.pPublic = (char *)strY.toStdString().c_str();

                ret = JS_PKI_encodeDSAPublicKey( &sDSAKey, &binPub );
                if( ret != 0 ) goto end;

                ret = JS_PKI_DSA_encodeSign( &binR, &binS, &binSign );
                if( ret != 0 ) goto end;

                ret = JS_PKI_DSA_Verify( strUseHash.toStdString().c_str(), &binMsg, &binSign, &binPub );
                if( ret == JSR_VERIFY )
                    bRes = true;
                else
                    bRes = false;

                jRspTestObj["testPassed"] = bRes;

                ret = 0;
            }
            else
            {
                manApplet->warnLog( tr("Invalid Mode: %1").arg( strMode ), this );
                ret = -1;
                goto end;
            }
        }
        else
        {
            manApplet->warnLog( tr("Invalid test type: %1").arg( strTestType), this );
            ret = -1;
            goto end;
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binSign );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binS );
    JS_BIN_reset( &binY );

    JS_BIN_reset( &binParam );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );

    return ret;
}
*/

int CAVPDlg::macJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    QString strDirection = jObject["direction"].toString();
    int nTgId = jObject["tgId"].toInt();
    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    QString strSymAlg;
    QString strMode;

    if( _getAlgMode( strAlg, strSymAlg, strMode ) != 0 )
        return -1;

    BIN binMsg = {0,0};
    BIN binKey = {0,0};
    BIN binIV = {0,0};
    BIN binAAD = {0,0};
    BIN binMAC = {0,0};
    BIN binTag = {0,0};

    int nAadLen = jObject["aadLen"].toInt();
    QString strIvGen = jObject["ivGen"].toString();
    int nPayloadLen = jObject["payloadLen"].toInt();
    int nIVLen = jObject["ivLen"].toInt();
    int nTagLen = jObject["tagLen"].toInt();

    long hSession = mSessionText->text().toLong();
    CryptokiAPI *pAPI = manApplet->cryptokiAPI();


    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();

        QString strMsg;
        QString strKey = jObj["key"].toString();
        QString strMAC = jObj["mac"].toString();

        QString strAad = jObj["aad"].toString();
        QString strIv = jObj["iv"].toString();
        QString strTag = jObj["tag"].toString();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        if( strMode == "AES" && strSymAlg == "CMAC" )
            strMsg = jObj["message"].toString();
        else
            strMsg = jObj["msg"].toString();

        JS_BIN_reset( &binMsg );
        JS_BIN_reset( &binKey );
        JS_BIN_reset( &binIV );
        JS_BIN_reset( &binAAD );
        JS_BIN_reset( &binMAC );
        JS_BIN_reset( &binTag );

        if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );
        if( strKey.length() > 0 ) JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
        if( strMAC.length() > 0 ) JS_BIN_decodeHex( strMAC.toStdString().c_str(), &binMAC );
        if( strAad.length() > 0 ) JS_BIN_decodeHex( strAad.toStdString().c_str(), &binAAD );
        if( strIv.length() > 0 ) JS_BIN_decodeHex( strIv.toStdString().c_str(), &binIV );
        if( strTag.length() > 0 ) JS_BIN_decodeHex( strTag.toStdString().c_str(), &binTag );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        long uObj = -1;
        if( strAlg == "AES" )
            createKey( CKK_AES, &binKey, &uObj );
        else
            createKey( CKK_GENERIC_SECRET, &binKey, &uObj );

        if( strTestType == "AFT" )
        {
            CK_MECHANISM sMech;
            unsigned char sOut[2048];
            int nOutLen = 2048;

            memset( &sMech, 0x00, sizeof(sMech));

            if( strDirection == "decrypt" || strDirection == "ver" )
            {
                bool bRes = false;
                BIN binGenMAC = {0,0};

                if( strMode == "GMAC" )
                {
                    /*
                    ret = JS_PKI_genGMAC( strSymAlg.toStdString().c_str(), &binAAD, &binKey, &binIV, &binGenMAC );
                    if( ret != 0 ) goto end;

                    JS_BIN_copy( &binMAC, &binTag );
                    */
                }
                else if( strMode == "AES" && strSymAlg == "CMAC" )
                {
                    /*
                    QString strMACAlg;
                    ret = JS_PKI_genCMAC( strMACAlg.toStdString().c_str(), &binMsg, &binKey, &binGenMAC );
                    if( ret != 0 ) goto end;
                    */
                }
                else
                {
                    QString strUseHash = _getHashNameFromMAC( strAlg );
                    sMech.mechanism = _getCKM_Hash( strUseHash );

                    ret = pAPI->SignInit( hSession, &sMech, uObj );
                    if( ret != 0 ) goto end;

                    ret = pAPI->Sign( hSession, binMsg.pVal, binMsg.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                    if( ret != 0 ) goto end;

                    JS_BIN_set( &binGenMAC, sOut, nOutLen );
                }

                if( JS_BIN_cmp( &binGenMAC, &binMAC ) == 0 )
                    bRes = true;
                else
                    bRes = false;

                jRspTestObj["testPassed"] = bRes;
            }
            else
            {
                if( strMode == "GMAC" )
                {
                    /*
                    ret = JS_PKI_genGMAC( strSymAlg.toStdString().c_str(), &binAAD, &binKey, &binIV, &binMAC );
                    if( ret != 0 ) goto end;

                    jRspTestObj["tag"] = getHexString( &binMAC );
                    */
                }
                else if( strMode == "AES" && strSymAlg == "CMAC" )
                {
                    /*
                    QString strMACAlg;

                    ret = JS_PKI_genCMAC( strMACAlg.toStdString().c_str(), &binMsg, &binKey, &binMAC );
                    if( ret != 0 ) goto end;
                    jRspTestObj["mac"] = getHexString( &binMAC );
                    */
                }
                else
                {
                    QString strUseHash = _getHashNameFromMAC( strAlg );
                    sMech.mechanism = _getCKM_Hash( strUseHash );

                    ret = pAPI->SignInit( hSession, &sMech, uObj );
                    if( ret != 0 ) goto end;

                    ret = pAPI->Sign( hSession, binMsg.pVal, binMsg.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                    if( ret != 0 ) goto end;

                    JS_BIN_set( &binMAC, sOut, nOutLen );

                    jRspTestObj["mac"] = getHexString( &binMAC );
                }
            }
        }
        else
        {
            manApplet->warnLog( tr("Invalid test type: %1").arg( strTestType), this );
            ret = -1;
            goto end;
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );

        if( uObj > 0 ) pAPI->DestroyObject( hSession, uObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binAAD );
    JS_BIN_reset( &binMAC );
    JS_BIN_reset( &binTag );

    return ret;
}

int CAVPDlg::blockCipherJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    QString strDirection = jObject["direction"].toString();
    int nTgId = jObject["tgId"].toInt();
    int nKeyLen = jObject["keyLen"].toInt();

    QString strSymAlg;
    QString strMode;

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    if( _getAlgMode( strAlg, strSymAlg, strMode ) != 0 )
        return -1;

    int nAADLen = jObject["aadLen"].toInt();
    QString strIVGen = jObject["ivGen"].toString();
    int nIVLen = jObject["ivLen"].toInt();
    int nPayLoadLen = jObject["payloadLen"].toInt();
    int nTagLen = jObject["tagLen"].toInt();

    QString strKwCipher = jObject["kwCipher"].toString();

    BIN binKey = {0,0};
    BIN binCT = {0,0};
    BIN binPT = {0,0};
    BIN binIV = {0,0};
    BIN binTag = {0,0};
    BIN binAAD = {0,0};

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 1024;

    long uObj = -1;

    CK_MECHANISM sMech;
    memset( &sMech, 0x00, sizeof(sMech));

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();
        QString strMsg = jObj["msg"].toString();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        QString strPT = jObj["pt"].toString();
        QString strCT = jObj["ct"].toString();
        QString strIV = jObj["iv"].toString();
        QString strKey = jObj["key"].toString();

        QString strAAD = jObj["aad"].toString();
        QString strTag = jObj["tag"].toString();

        JS_BIN_reset( &binKey );
        JS_BIN_reset( &binCT );
        JS_BIN_reset( &binPT );
        JS_BIN_reset( &binIV );
        JS_BIN_reset( &binTag );
        JS_BIN_reset( &binAAD );

        if( strPT.length() > 0 ) JS_BIN_decodeHex( strPT.toStdString().c_str(), &binPT );
        if( strCT.length() > 0 ) JS_BIN_decodeHex( strCT.toStdString().c_str(), &binCT );
        if( strIV.length() > 0 ) JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
        if( strKey.length() > 0 ) JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
        if( strAAD.length() > 0 ) JS_BIN_decodeHex( strAAD.toStdString().c_str(), &binAAD );
        if( strTag.length() > 0 ) JS_BIN_decodeHex( strTag.toStdString().c_str(), &binTag );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "MCT" )
        {
            QJsonArray jSymArr;

            unsigned char sOut[1024];
            int nOutLen = 1024;
            int nKeyAlg = CKK_AES;

            if( strMode == "CCM" || strMode == "GCM" )
                return -2;

            if( strMode == "CFB128" ) strMode = "CFB";

            if( strDirection == "encrypt" )
            {
                if( strMode == "ECB" )
                    ret = makeSymECB_MCT( nKeyAlg, &binKey, &binPT, jSymArr );
                else if( strMode == "CBC" )
                    ret = makeSymCBC_MCT( nKeyAlg, &binKey, &binIV, &binPT, jSymArr );
                else if( strMode == "CTR" )
                    ret = makeSymCTR_MCT( nKeyAlg, &binKey, &binIV, &binPT, jSymArr );
                else if( strMode == "CFB" )
                    ret = makeSymCFB_MCT( nKeyAlg, &binKey, &binIV, &binPT, jSymArr );
                else if( strMode == "OFB" )
                    ret = makeSymOFB_MCT( nKeyAlg, &binKey, &binIV, &binPT, jSymArr );
            }
            else
            {
                if( strMode == "ECB" )
                    ret = makeSymDecECB_MCT( nKeyAlg, &binKey, &binCT, jSymArr );
                else if( strMode == "CBC" )
                    ret = makeSymDecCBC_MCT( nKeyAlg, &binKey, &binIV, &binCT, jSymArr );
                else if( strMode == "CTR" )
                    ret = makeSymDecCTR_MCT( nKeyAlg, &binKey, &binIV, &binCT, jSymArr );
                else if( strMode == "CFB" )
                    ret = makeSymDecCFB_MCT( nKeyAlg, &binKey, &binIV, &binCT, jSymArr );
                else if( strMode == "OFB" )
                    ret = makeSymDecOFB_MCT( nKeyAlg, &binKey, &binIV, &binCT, jSymArr );
            }

            if( ret != 0 ) goto end;

            jRspTestObj["resultsArray"] = jSymArr;
        }
        else if( strTestType == "CTR" )
        {
            int nLeft = 0;
            int nBlock = 16;
            int nPos = 0;
            BIN binPart = {0,0};
            BIN binRes = {0,0};

            QString strCipher;
 //           strCipher = getSymAlg( strSymAlg, strMode, nKeyLen/8 );

            if( strMode.toUpper() != "CTR" )
                return -2;

            sMech.mechanism = _getCKM_Cipher( strSymAlg, strMode );
            sMech.pParameter = binIV.pVal;
            sMech.ulParameterLen = binIV.nLen;

            ret = createKey( CKK_AES, &binKey, &uObj );
            if( ret != 0 ) goto end;

            if( strDirection == "encrypt" )
            {
                nLeft = binPT.nLen;

                ret = pAPI->EncryptInit( hSession, &sMech, uObj );
                if( ret != 0 ) goto end;

                while( nLeft > 0 )
                {
                    if( nLeft < nBlock ) nBlock = nLeft;

                    binPart.nLen = nBlock;
                    binPart.pVal = &binPT.pVal[nPos];

 //                   ret = JS_PKI_encryptData( strCipher.toStdString().c_str(), 0, &binPart, &binIV, &binKey, &binRes );

                    nOutLen = sizeof(sOut);

                    ret = pAPI->Encrypt( hSession, binPart.pVal, binPart.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                    if( ret != 0 ) return ret;

                    JS_BIN_set( &binRes, sOut, nOutLen );

                    JS_BIN_appendBin( &binCT, &binRes );
                    JS_BIN_reset( &binRes );
                    JS_BIN_DEC( &binIV );

                    nLeft -= nBlock;
                    nPos += nBlock;
                }

                jRspTestObj["ct"] = getHexString( &binCT );
            }
            else
            {
                nLeft = binCT.nLen;

                ret = pAPI->EncryptInit( hSession, &sMech, uObj );
                if( ret != 0 ) goto end;

                while( nLeft > 0 )
                {
                    if( nLeft < nBlock ) nBlock = nLeft;

                    binPart.nLen = nBlock;
                    binPart.pVal = &binCT.pVal[nPos];

//                    ret = JS_PKI_encryptData( strCipher.toStdString().c_str(), 0, &binPart, &binIV, &binKey, &binRes );

                    nOutLen = sizeof(sOut);

                    ret = pAPI->Encrypt( hSession, binPart.pVal, binPart.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                    if( ret != 0 ) return ret;

                    JS_BIN_set( &binRes, sOut, nOutLen );

                    JS_BIN_appendBin( &binPT, &binRes );
                    JS_BIN_reset( &binRes );
                    JS_BIN_DEC( &binIV );

                    nLeft -= nBlock;
                    nPos += nBlock;
                }

                jRspTestObj["pt"] = getHexString( &binPT );
            }

            if( uObj > 0 ) pAPI->DestroyObject( hSession, uObj );
        }
        else // AFT
        {
            QString strCipher;
 //           strCipher = getSymAlg( strSymAlg, strMode, nKeyLen/8 );

            if( strDirection == "encrypt" )
            {
                ret = createKey( CKK_AES, &binKey, &uObj );
                if( ret != 0 ) goto end;

                if( strMode.toUpper() == "GCM" || strMode.toUpper() == "CCM" )
                {
                    if( strMode == "CCM" )
                    {
                        setAES_CCMParam( &binIV, &binAAD, binPT.nLen, nTagLen/8, &sMech );

                        ret = pAPI->EncryptInit( hSession, &sMech, uObj );
                        if( ret != 0 ) goto end;

                        ret = pAPI->Encrypt( hSession, binPT.pVal, binPT.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                        if( ret != 0 ) goto end;

                        JS_BIN_set( &binTag, sOut, nTagLen/8 );
                        JS_BIN_set( &binCT, &sOut[nTagLen/8], nOutLen - nTagLen/8 );

                        JS_BIN_appendBin( &binCT, &binTag );
                        jRspTestObj["ct"] = getHexString( &binCT );
                    }
                    else
                    {
                        setAES_GCMParam( &binIV, &binAAD, nTagLen/8, &sMech );

                        ret = pAPI->EncryptInit( hSession, &sMech, uObj );
                        if( ret != 0 ) goto end;

                        ret = pAPI->Encrypt( hSession, binPT.pVal, binPT.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                        if( ret != 0 ) goto end;

                        JS_BIN_set( &binTag, sOut, nTagLen/8 );
                        JS_BIN_set( &binCT, &sOut[nTagLen/8], nOutLen - nTagLen/8 );

                        JS_BIN_appendBin( &binCT, &binTag );
                        jRspTestObj["ct"] = getHexString( &binCT );

                        if( ret != 0 ) goto end;

                        jRspTestObj["tag"] = getHexString( &binTag );
                        jRspTestObj["ct"] = getHexString( &binCT );
                    }
                }
                else if( strMode.toUpper() == "KW" || strMode.toUpper() == "KWP" )
                {
                    long uWrappingObj = -1;
                    long uObj = -1;

                    if( strMode == "KWP" )
                    {
                        sMech.mechanism = CKM_AES_KEY_WRAP_PAD;
                    }
                    else
                    {
                        sMech.mechanism = CKM_AES_KEY_WRAP;
                    }

                    if( strKwCipher == "inverse" )
                    {
                        manApplet->elog( QString( "KwCiper(%1) does not support" ).arg( strKwCipher ));
                        ret = -1;
                        goto end;
                    }

                    ret = createKey( CKK_AES, &binKey, &uWrappingObj );
                    if( ret != 0 ) goto end;

                    ret = createKey( CKK_GENERIC_SECRET, &binPT, &uObj );
                    if( ret != 0 ) goto end;

                    ret = pAPI->WrapKey( hSession, &sMech, uWrappingObj, uObj, sOut, (CK_ULONG_PTR)&nOutLen );
                    if( ret != 0 ) goto end;

                    JS_BIN_set( &binCT, sOut, nOutLen );

                    jRspTestObj["ct"] = getHexString( &binCT );

                    if( uWrappingObj > 0 ) pAPI->DestroyObject( hSession, uWrappingObj );
                    if( uObj > 0 ) pAPI->DestroyObject( hSession, uObj );
                }
                else
                {
                    long uObj = -1;

                    memset( &sMech, 0x00, sizeof(sMech));
                    sMech.mechanism = _getCKM_Cipher( strSymAlg, strMode );


                    ret = pAPI->EncryptInit( hSession, &sMech, uObj );
                    if( ret != 0 ) goto end;

                    nOutLen = sizeof(sOut);
                    ret = pAPI->Encrypt( hSession, binPT.pVal, binPT.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                    if( ret != 0 ) goto end;

                    JS_BIN_set( &binCT, sOut, nOutLen );


                    jRspTestObj["ct"] = getHexString( &binCT );
                }

                if( uObj > 0 ) pAPI->DestroyObject( hSession, uObj );
            }
            else
            {
                long uObj = -1;
                ret = createKey( CKK_AES, &binKey, &uObj );
                if( ret != 0 ) goto end;

                if( strMode.toUpper() == "GCM" || strMode.toUpper() == "CCM" )
                {
                    if( strMode == "CCM" )
                    {
                        int nTagBytes = nTagLen / 8;

                        setAES_CCMParam( &binIV, &binAAD, binCT.nLen, nTagBytes, &sMech );
                        JS_BIN_set( &binTag, &binCT.pVal[binCT.nLen-nTagBytes], nTagBytes );
                        binCT.nLen = binCT.nLen - nTagBytes;

                        ret = pAPI->DecryptInit( hSession, &sMech, uObj );
                        if( ret != 0 ) goto end;

                        nOutLen = sizeof(sOut);
                        ret = pAPI->Decrypt( hSession, binCT.pVal, binCT.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                        if( ret != 0 ) goto end;

                        JS_BIN_set( &binPT, sOut, nOutLen );
                    }
                    else
                    {
                        int nTagBytes = nTagLen / 8;

                        setAES_GCMParam( &binIV, &binAAD, nTagBytes, &sMech );
                        JS_BIN_set( &binTag, &binCT.pVal[binCT.nLen-nTagBytes], nTagBytes );
                        binCT.nLen = binCT.nLen - nTagBytes;

                        ret = pAPI->DecryptInit( hSession, &sMech, uObj );
                        if( ret != 0 ) goto end;

                        nOutLen = sizeof(sOut);
                        ret = pAPI->Decrypt( hSession, binCT.pVal, binCT.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                        if( ret != 0 ) goto end;

                        JS_BIN_set( &binPT, sOut, nOutLen );

                    }

                    if( ret == 0 )
                        jRspTestObj["pt"] = getHexString( &binPT );
                    else
                        jRspTestObj["testPassed"] = false;

                    ret = 0;
                }
                else if( strMode.toUpper() == "KW" || strMode.toUpper() == "KWP" )
                {
                    long uWrappingObj = -1;
                    long uObj = -1;
                    CK_ATTRIBUTE sTemplate[10];
                    int nCount = 0;

                    if( strMode == "KWP" )
                    {
                        sMech.mechanism = CKM_AES_KEY_WRAP_PAD;
                    }
                    else
                    {
                        sMech.mechanism = CKM_AES_KEY_WRAP;
                    }

                    ret = createKey( CKK_AES, &binKey, &uWrappingObj );
                    if( ret != 0 ) goto end;

                    ret = pAPI->UnwrapKey( hSession, &sMech, uWrappingObj, binCT.pVal, binCT.nLen, sTemplate, nCount, (CK_OBJECT_HANDLE_PTR)&uObj );
                    if( ret != 0 ) goto end;

                    ret = pAPI->GetAttributeValue2( hSession, uObj, CKA_VALUE, &binPT );
                    if( ret != 0 ) goto end;

                    if( ret == 0 )
                        jRspTestObj["pt"] = getHexString( &binPT );
                    else
                        jRspTestObj["testPassed"] = false;

                    ret = 0;
                }
                else
                {
                    long uObj = -1;

                    memset( &sMech, 0x00, sizeof(sMech));
                    sMech.mechanism = _getCKM_Cipher( strSymAlg, strMode );


                    ret = pAPI->DecryptInit( hSession, &sMech, uObj );
                    if( ret != 0 ) goto end;

                    nOutLen = sizeof(sOut);
                    ret = pAPI->Decrypt( hSession, binCT.pVal, binCT.nLen, sOut, (CK_ULONG_PTR)&nOutLen );
                    if( ret != 0 ) goto end;

                    JS_BIN_set( &binPT, sOut, nOutLen );

                    jRspTestObj["pt"] = getHexString( &binPT );

                    if( ret != 0 ) goto end;
                }

                if( uObj > 0 ) pAPI->DestroyObject( hSession, uObj );
            }
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binCT );
    JS_BIN_reset( &binPT );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binTag );
    JS_BIN_reset( &binAAD );

    return ret;
}

int CAVPDlg::kdaJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    // For KAS-ECC
    QString strCurve = jObject["curve"].toString();
    QString strUseCurve = _getECCurveName( strCurve );

    // For kdf-components
    int nFieldSize = jObject["fieldSize"].toInt();
    QString strHashAlg = jObject["hashAlg"].toString();
    int nKeyDataLength = jObject["keyDataLength"].toInt();
    int nSharedInfoLength = jObject["sharedInfoLength"].toInt();

    QString strHmacAlg = jObject["hmacAlg"].toString();

    QString strUseHash;

    if( strHashAlg.length() > 0 )
        strUseHash = _getHashName( strHashAlg );
    else if( strHmacAlg.length() > 0 )
        strUseHash = _getHashName( strHmacAlg );

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    BIN binKey = {0,0};
    BIN binInfo = {0,0};
    BIN binSecret = {0,0};

    BIN binPubSrvX = {0,0};
    BIN binPubSrvY = {0,0};

    BIN binSalt = {0,0};
    BIN binDerivedKey = {0,0};

    CryptokiAPI *pAPI = manApplet->cryptokiAPI();
    long hSession = mSessionText->text().toLong();

    unsigned char sOut[1024];
    int nOutLen = 1024;


    CK_MECHANISM sMech;
    memset( &sMech, 0x00, sizeof(sMech));

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        //kdf-components
        QString strSharedInfo = jObj["sharedInfo"].toString();
        QString strZ = jObj["z"].toString();

        // KAS-ECC
        QString strPublicServerX = jObj["publicServerX"].toString();
        QString strPublicServerY = jObj["publicServerY"].toString();

        // PBKDF
        int nKeyLen = jObj["keyLen"].toInt();
        int nIterCount = jObj["iterationCount"].toInt();
        QString strPassword = jObj["password"].toString(); // Base64 encoding
        QString strSalt = jObj["salt"].toString();

        JS_BIN_reset( &binKey );
        JS_BIN_reset( &binInfo );
        JS_BIN_reset( &binSecret );

        JS_BIN_reset( &binPubSrvX );
        JS_BIN_reset( &binPubSrvY );

        JS_BIN_reset( &binDerivedKey );
        JS_BIN_reset( &binSalt );

        if( strSharedInfo.length() > 0 ) JS_BIN_decodeHex( strSharedInfo.toStdString().c_str(), &binInfo );
        if( strZ.length() > 0 ) JS_BIN_decodeHex( strZ.toStdString().c_str(), &binSecret );

        if( strPublicServerX.length() > 0 ) JS_BIN_decodeHex( strPublicServerX.toStdString().c_str(), &binPubSrvX );
        if( strPublicServerY.length() > 0 ) JS_BIN_decodeHex( strPublicServerY.toStdString().c_str(), &binPubSrvY );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "AFT" )
        {
            if( strAlg == "kdf-components" )
            {
                ret = JS_PKI_KDF_X963( &binSecret, &binInfo, strUseHash.toStdString().c_str(), nKeyDataLength/8, &binKey );
                if( ret != 0 ) goto end;

                jRspTestObj["keyData"] = getHexString( &binKey );
            }
            else if( strAlg == "KAS-ECC" )
            {
                BIN binPri = {0,0};
                BIN binPub = {0,0};
                BIN binPubX = {0,0};
                BIN binPubY = {0,0};

                JECKeyVal sECKey;
                long uPri = -1;
                long uPub = -1;
                long uObj = -1;

                CK_ATTRIBUTE sTemplate[10];
                int nCount = 0;

                CK_ECDH1_DERIVE_PARAMS sParam;

                memset( &sParam, 0x00, sizeof(sParam));

                memset( &sECKey, 0x00, sizeof(sECKey));

                CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
                int nKeyType = CKK_GENERIC_SECRET;

                int uKeyLen = -1;


                ret = genECCKeyPair( strUseCurve, &uPri, &uPub );
                if( ret != 0 ) goto end;

                if( strCurve == "P-256" )
                {
                    uKeyLen = 32;
                }
                else if( strCurve == "P-384" )
                {
                    uKeyLen = 48;
                }

                sTemplate[nCount].type = CKA_CLASS;
                sTemplate[nCount].pValue = &keyClass;
                sTemplate[nCount].ulValueLen = sizeof(keyClass);
                nCount++;

                sTemplate[nCount].type = CKA_KEY_TYPE;
                sTemplate[nCount].pValue = &nKeyType;
                sTemplate[nCount].ulValueLen = sizeof(nKeyType);
                nCount++;

                sTemplate[nCount].type = CKA_VALUE_LEN;
                sTemplate[nCount].pValue = &uKeyLen;
                sTemplate[nCount].ulValueLen = sizeof(long);
                nCount++;

                sTemplate[nCount].type = CKA_EXTRACTABLE;
                sTemplate[nCount].pValue = &kTrue;
                sTemplate[nCount].ulValueLen = sizeof(CK_BBOOL);
                nCount++;

                JS_BIN_decodeHex( strPublicServerX.toStdString().c_str(), &binPubX );
                JS_BIN_decodeHex( strPublicServerY.toStdString().c_str(), &binPubY );

                JS_BIN_copy( &binPub, &binPubX );
                JS_BIN_appendBin( &binPub, &binPubY );

                sMech.mechanism = CKM_ECDH1_DERIVE;

                sParam.kdf = CKD_NULL;
                sParam.pPublicData = binPub.pVal;
                sParam.ulPublicDataLen = binPub.nLen;

                sMech.pParameter = &sParam;
                sMech.ulParameterLen = sizeof(sParam);

                ret = pAPI->DeriveKey( hSession, &sMech, uPri, sTemplate, nCount, (CK_OBJECT_HANDLE_PTR)&uObj );
                if( ret != 0 ) goto end;

                ret = pAPI->GetAttributeValue2( hSession, uObj, CKA_VALUE, &binSecret );
                if( ret != 0 ) goto end;

                ret = pAPI->getECCKeyVal( hSession, uPri, &sECKey );
                if( ret != 0 ) goto end;


                jRspTestObj["publicIutX"] = sECKey.pPubX;
                jRspTestObj["publicIutY"] = sECKey.pPubY;
                jRspTestObj["z"] = getHexString( &binSecret );

                JS_PKI_resetECKeyVal( &sECKey );

                JS_BIN_reset( &binPri );
                JS_BIN_reset( &binPub );
                JS_BIN_reset( &binPubX );
                JS_BIN_reset( &binPubY );
            }
            else if( strAlg == "PBKDF" )
            {
                JS_BIN_decodeHex( strSalt.toStdString().c_str(), &binSalt );

                ret = JS_PKI_PBKDF2( strPassword.toStdString().c_str(), &binSalt, nIterCount, strUseHash.toStdString().c_str(), nKeyLen/8, &binDerivedKey );
                if( ret != 0 ) goto end;

                jRspTestObj["derivedKey"] = getHexString( &binDerivedKey );
            }
        }
        else
        {
            manApplet->warnLog( tr("Invalid test type: %1").arg( strTestType), this );
            ret = -1;
            goto end;
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binInfo );
    JS_BIN_reset( &binSecret );

    JS_BIN_reset( &binPubSrvX );
    JS_BIN_reset( &binPubSrvY );

    JS_BIN_reset( &binDerivedKey );
    JS_BIN_reset( &binSalt );

    return ret;
}
