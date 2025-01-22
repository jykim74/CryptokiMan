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

const QStringList kSymAlgList = { "AES", "DES3" };
const QStringList kSymModeList = { "ECB", "CBC", "CTR", "CFB", "OFB" };
const QStringList kSymDirection = { "Encrypt", "Decrypt" };
const QStringList kHashAlgList = { "SHA-1", "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512" };
const QStringList kMctVersion = { "Standard", "Alternate" };

CAVPDlg::CAVPDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mFindRspBtn, SIGNAL(clicked()), this, SLOT(clickFindRsp()));
    connect( mMCT_SymClearBtn, SIGNAL(clicked()), this, SLOT(clickMCT_SymClear()));
    connect( mMCT_HashClearBtn, SIGNAL(clicked()), this, SLOT(clickMCT_HashClear()));
    connect( mMCT_SymRunBtn, SIGNAL(clicked()), this, SLOT(clickMCT_SymRun()));
    connect( mMCT_HashRunBtn, SIGNAL(clicked()), this, SLOT(clickMCT_HashRun()));

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

    mACVP_HashCombo->addItems( kHashAlgList );

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

