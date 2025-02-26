#ifndef CAVP_DLG_H
#define CAVP_DLG_H

#include <QDialog>
#include "ui_cavp_dlg.h"
#include "js_bin.h"
#include "js_pkcs11.h"

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

namespace Ui {
class CAVPDlg;
}

static QString _getHashName( const QString strACVPHash );
static QString _getECCurveName( const QString strACVPCurve );
static int _getEdDSAType( const QString strACVPCurve );
static int _getAlgMode( const QString strAlg, QString& strSymAlg, QString& strMode );
static QString _getHashNameFromMAC( const QString strACVPMac );
int getACVPType( const QString strAlg );
int _getCKK( const QString strAlg );
int _getCKM_Cipher( const QString strAlg, const QString strMode );
int _getCKM_HMAC( const QString strHash );
int _getCKM_Hash( const QString strHash );
int _getCKM_ECDSA( const QString strHash );
int _getCKM_RSA( const QString strHash, bool bPSS = false );

void _setMechRSA_PSS( const QString strHash, CK_MECHANISM_PTR pMech );
void _setMechRSA_OAEP( CK_MECHANISM_PTR pMech );

class CAVPDlg : public QDialog, public Ui::CAVPDlg
{
    Q_OBJECT

public:
    explicit CAVPDlg(QWidget *parent = nullptr);
    ~CAVPDlg();

    void setSelectedSlot( int index );

private slots:
    void slotChanged( int index );
    void clickFindRsp();
    void clickACVPFindJson();

    void changeECCAlg(int index);
    void changeRSAAlg(int index);
    void changeECCType(int index);
    void changeRSAType(int index);

    void checkACVPSetTgId();
    void checkACVPSetTcId();

    void MCT_KeyChanged( const QString& text );
    void MCT_IVChanged( const QString& text );
    void MCT_PTChanged( const QString& text );
    void MCT_CTChanged( const QString& text );
    void MCT_LastKeyChanged( const QString& text );
    void MCT_LastIVChanged( const QString& text );
    void MCT_LastPTChanged( const QString& text );
    void MCT_LastCTChanged( const QString& text );

    void MCT_SeedChanged( const QString& text );
    void MCT_FirstMDChanged( const QString& text );
    void MCT_LastMDChanged( const QString& text );

    void clickSymRun();
    void clickAERun();
    void clickHashRun();
    void clickMACRun();
    void clickECCRun();
    void clickRSARun();

    void clickSymFind();
    void clickAEFind();
    void clickHashFind();
    void clickMACFind();
    void clickECCFind();
    void clickRSAFind();

    void clickRSA_DETPriKeyFind();

    void clickMCT_SymClear();
    void clickMCT_HashClear();
    void clickMCT_SymRun();
    void clickMCT_HashRun();

    void clickACVP_Clear();
    void clickACVP_Run();
    void clickACVP_LDTClear();
    void clickACVP_LDTRun();


private:
    void initUI();
    void initialize();
    void logRsp( const QString strLog );
    QString getRspFile(const QString &reqFileName, const QString strExt = "rsp" );
    int getNameValue( const QString strLine, QString& name, QString& value );

    int makeSymData( const QString strAlgMode, const BIN *pKey, const BIN *pIV, const BIN *pPT );
    int makeAEData( const BIN *pKey, const BIN *pIV, const BIN *pPT, const BIN *pAAD, int nTagLen, int nSrcLen );
    int makeADData( const BIN *pKey, const BIN *pIV, const BIN *pCT, const BIN *pAAD, const BIN *pTag, int nSrcLen );
    int makeHashData( int nLen, const BIN *pVal );
    int makeHMACData( const QString strCount, const QString strKLen, const QString strTLen, const BIN *pKey, const BIN *pMsg );

    int makeRSA_ES_DET( const QString strPri, const QString strC );
    int makeRSA_ES_ENT( int nE, const QString strN, const QString strM );
    int makeRSA_ES_KGT( int nKeyLen, int nE, int nCount );

    int makeRSA_PSS_KPG( int nLen, int nE, int nCount );
    int makeRSA_PSS_SGT( int nE, const QString strPri, const QString strHash, const QString strM );
    int makeRSA_PSS_SVT( int nE, const QString strN, const QString strHash, const QString strM, const QString strS );

    int makeECDH_KPG( const QString strParam, int nCount );
    int makeECDH_PKV( const QString strParam, const QString strPubX, const QString strPubY );
    int makeECDH_KAKAT( const QString strParam, const QString strRA, const QString strRB, const QString strKTA1X, const QString strKTA1Y );

    int makeECDSA_KPG( const QString strParam, int nNum );
    int makeECDSA_PKV( const QString strParam, const QString strYX, const QString strYY );
    int makeECDSA_SGT( const QString strParam, const QString strHash, const QString strM );
    int makeECDSA_SVT( const QString strParam, const QString strHash, const QString strM, const QString strYX, const QString strYY, const QString strR, const QString strS );


    int makeSym_MCT( const QString strAlgMode, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymDec_MCT( const QString strAlgMode, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin = false );

    int makeSymECB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pPT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymCBC_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymCTR_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymCFB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymOFB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin = false );

    /* Need to support decrypt */
    int makeSymDecECB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pCT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymDecCBC_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymDecCTR_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymDecCFB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymDecOFB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin = false );

    int makeHash_MCT( const QString strAlg, const BIN *pSeed, QJsonArray& jsonRes, bool bWin = false );
    int makeHash_AlternateMCT( const QString strAlg, const BIN *pSeed, QJsonArray& jsonRes, bool bWin = false );

    int createKey( int nKeyType, const BIN *pKey, long *phObj );
    int genRSAKeyPair( int nKeyLen, int nE, long *phPri, long *phPub );
    int importRSAPriKey( const BIN *pRSAPri, long *phPri );
    int importRSAPubKey( const BIN *pRSAPub, long *phPub );

    int genECCKeyPair( const QString strParam, long *phPri, long *phPub );
    int importECCPriKey( const BIN *pECCPri, long *phPri );
    int importECCPubKey( const BIN *pECCPub, long *phPub );

    int deriveKeyECDH( long uPri, const BIN *pPubX, const BIN *pPubY, long* phObj );

    bool isSkipTestType( const QString strTestType );
    void saveJsonRsp( const QJsonDocument& pJsonDoc );
    int readJsonReq( const QString strPath, QJsonDocument& pJsonDoc );
    int makeUnitJsonWork( const QString strAlg, const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject );
    int hashJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject );
    int ecdsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject );
    int rsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject );
//    int dsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject );
    int macJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject );
    int blockCipherJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject );
    int kdaJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject );


    void settingRspPath( const QString strPath );
    QString gettingRspPath();
    const QString setRspName( const QString strFileName );
    void clearRspName();

    bool checkValidMech( int nCKM_ID );

    long session_;
    int slot_index_;
    QString rsp_name_;
};

#endif // CAVP_DLG_H
