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
                BIN binKey = {0,0};
                BIN binIV = {0,0};
                BIN binPT = {0,0};

                if( strKey.length() > 0 ) logRsp( QString( "Key = %1").arg( strKey ));
                if( strIV.length() > 0 ) logRsp( QString( "IV = %1").arg( strIV ));
                if( strPT.length() > 0 ) logRsp( QString( "PT = %1").arg( strPT ));

                QString strAlgMode = QString( "%1-%2" ).arg( strAlg ).arg( strMode );

                if( strType == "MCT" )
                {
                    QJsonArray jArr;
                    ret = makeSym_MCT( strAlgMode, &binKey, &binIV, &binPT, jArr, false );
                }
                else
                {
                    ret = makeSymData( strAlgMode, &binKey, &binIV, &binPT );
                }


                JS_BIN_reset( &binKey );
                JS_BIN_reset( &binIV );
                JS_BIN_reset( &binPT );

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
    int ret = 0;
    manApplet->log( "AE execution" );

    if( mAEReqPathText->text().length() < 1 )
    {
        manApplet->warningBox( tr("Select requested file"), this );
        mAEReqPathText->setFocus();
        return;
    }

    QString strPath = mAEReqPathText->text();
    QFile reqFile( strPath );
    QString strAlg = mAEAlgCombo->currentText();


    QString strRspName = getRspFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        manApplet->elog( QString( "failed to open file(%1)\n").arg( strPath ));
        return;
    }

    int nPos = 0;
    int nLen = 0;
    QString strCount;
    QString strKey;
    QString strIV;
    QString strC;
    QString strT;
    QString strAdata;
    QString strPT;

    int nKeyLen = -1;
    int nIVLen = -1;
    int nPTLen = -1;
    int nAADLen = -1;
    int nTagLen = -1;

    QTextStream in( &reqFile );
    QString strLine = in.readLine();

    logRsp( QString( "# AE-%1-%2-%3 Response")
               .arg( mAEAlgCombo->currentText())
               .arg( mAEModeCombo->currentText())
               .arg( mAETypeCombo->currentText()) );

    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();
        //        manApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

        if( nLen > 0 )
        {
            strLine.remove( '[' );
            strLine.remove( ']' );

            getNameValue( strLine, strName, strValue );

            if( strName == "COUNT" )
                strCount = strValue;
            else if( strName == "Key" )
                strKey = strValue;
            else if( strName == "IV" )
                strIV = strValue;
            else if( strName == "C" )
                strC = strValue;
            else if( strName == "Adata" )
                strAdata = strValue;
            else if( strName == "PT" )
                strPT = strValue;
            else if( strName == "T" )
                strT = strValue;
            else if( strName == "KeyLen" )
                nKeyLen = strValue.toInt();
            else if( strName == "IVLen" )
                nIVLen = strValue.toInt();
            else if( strName == "PTLen" )
                nPTLen = strValue.toInt();
            else if( strName == "AADLen" )
                nAADLen = strValue.toInt();
            else if( strName == "TagLen" )
                nTagLen = strValue.toInt();
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( nKeyLen >= 0 && nIVLen >= 0 && nAADLen >= 0 && nPTLen >= 0 && nTagLen >= 0 )
            {
                logRsp( QString( "[KeyLen = %1]").arg( nKeyLen ));
                logRsp( QString( "[IVLen = %1]").arg(nIVLen));
                logRsp( QString( "[PTLen = %1]").arg( nPTLen ));
                logRsp( QString( "[AADLen = %1]").arg(nAADLen));
                logRsp( QString( "[TagLen = %1]").arg(nTagLen));
                logRsp( "" );

                nKeyLen = -1;
                nIVLen = -1;
                nAADLen = -1;
                nPTLen = -1;
            }

            if( mAETypeCombo->currentText() == "AD" )
            {
                if( strCount.length() > 0 && strKey.length() > 0 && strIV.length() > 0 && strT.length() > 0 )
                {
                    manApplet->log( QString( "COUNT = %1").arg( strCount ));
                    //                   ret = makeGCM_AD( RNX_ALG_ARIA, &binKey, &binIV, &binAdata, &binC, &binT );
                    //                    ret = makeADData( strKey, strIV, strC, strAdata, strT );

                    if( ret != 0 ) break;
                }
            }
            else
            {
                if( strCount.length() > 0 && strKey.length() > 0 && strIV.length() > 0 && nTagLen > 0 )
                {
                    manApplet->log( QString( "COUNT = %1").arg( strCount ));
                    //                   ret = makeGCM_AE( RNX_ALG_ARIA, &binKey, &binIV, &binAdata, &binPT, nTagLen / 8 );
                    //                    ret = makeAEData( strKey, strIV, strPT, strAdata, nTagLen/8 );

                    if( ret != 0 ) break;
                }
            }

            strCount.clear();
            strKey.clear();
            strIV.clear();
            strT.clear();
            strC.clear();
            strAdata.clear();
        }


        strLine = strNext;
        nPos++;
    }

    manApplet->messageBox( tr("CAVP completed[Rsp: %1]").arg(strRspName), this );
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
                BIN binMsg = {0,0};
                JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );

                ret = makeHashData( strLen.toInt(), &binMsg );
                JS_BIN_reset( &binMsg );
                if( ret != 0 ) return;
            }
            else if( strSeed.length() > 0 )
            {
                QJsonArray jArr;
                BIN binSeed = {0,0};
                ret = makeHash_MCT( mHashAlgCombo->currentText(), &binSeed, jArr );
                JS_BIN_reset( &binSeed );
                if( ret != 0 ) return;
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
                BIN binKey = {0,0};
                BIN binMsg = {0,0};

                JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
                JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );
                ret = makeHMACData( strCount, strKLen, strTLen, &binKey, &binMsg );

                JS_BIN_reset( &binKey );
                JS_BIN_reset( &binMsg );

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

    QString strAlg = mECCAlgCombo->currentText();

    logRsp( QString( "# ECC-%1-%2-%3 Response")
               .arg( strAlg )
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
            if( strAlg == "ECDSA" && mECCTypeCombo->currentText() == "KPG" )
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
            else if( strAlg == "ECDSA" && mECCTypeCombo->currentText() == "PKV" )
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
            else if( strAlg == "ECDSA" && mECCTypeCombo->currentText() == "SGT" )
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
            else if( strAlg == "ECDSA" && mECCTypeCombo->currentText() == "SVT" )
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
            else if( strAlg == "ECDH" && mECCTypeCombo->currentText() == "KPG" )
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
            else if( strAlg == "ECDH" && mECCTypeCombo->currentText() == "PKV" )
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
            else if( strAlg == "ECDH" && mECCTypeCombo->currentText() == "KAKAT" )
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
    QString strAlg = mRSAAlgCombo->currentText();

    BIN binPri = {0,0};
    BIN binPub = {0,0};

    logRsp( QString( "# RSA-%1-%2 Response")
               .arg( strAlg )
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
            if( strAlg == "RSAPSS" && mRSATypeCombo->currentText() == "KPG" )
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
            else if( strAlg == "RSAPSS" && mRSATypeCombo->currentText() == "SGT" )
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
            else if( strAlg == "RSAPSS" && mRSATypeCombo->currentText() == "SVT" )
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
            else if( strAlg == "RSAES" && mRSATypeCombo->currentText() == "DET" )
            {
                if( bInit == true )
                {
                    QString strPriPath;
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
            else if( strAlg == "RSAES" && mRSATypeCombo->currentText() == "ENT" )
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
            else if( strAlg == "RSAES" && mRSATypeCombo->currentText() == "KGT" )
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

            if( strAlg == "ES" ) strHash.clear();
        }


        strLine = strNext;
        nPos++;
    }

    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );

    manApplet->messageBox( tr("CAVP completed[Rsp: %1]").arg(strRspName), this );
}

void CAVPDlg::clickSymFind()
{
    QString strRspPath = mSymReqPathText->text();
    if( strRspPath.length() < 1 ) strRspPath = manApplet->curPath();

    QString strFileName = findFile( this, JS_FILE_TYPE_TXT, strRspPath );
    if( strFileName.length() > 0 )
    {
        mSymReqPathText->setText( strFileName );
    }
}

void CAVPDlg::clickAEFind()
{
    QString strRspPath = mAEReqPathText->text();
    if( strRspPath.length() < 1 ) strRspPath = manApplet->curPath();

    QString strFileName = findFile( this, JS_FILE_TYPE_TXT, strRspPath );
    if( strFileName.length() > 0 )
    {
        mAEReqPathText->setText( strFileName );
    }
}

void CAVPDlg::clickHashFind()
{
    QString strRspPath = mHashReqPathText->text();
    if( strRspPath.length() < 1 ) strRspPath = manApplet->curPath();

    QString strFileName = findFile( this, JS_FILE_TYPE_TXT, strRspPath );
    if( strFileName.length() > 0 )
    {
        mHashReqPathText->setText( strFileName );
    }
}

void CAVPDlg::clickMACFind()
{
    QString strRspPath = mMACReqPathText->text();
    if( strRspPath.length() < 1 ) strRspPath = manApplet->curPath();

    QString strFileName = findFile( this, JS_FILE_TYPE_TXT, strRspPath );
    if( strFileName.length() > 0 )
    {
        mMACReqPathText->setText( strFileName );
    }
}

void CAVPDlg::clickECCFind()
{
    QString strRspPath = mECCReqPathText->text();
    if( strRspPath.length() < 1 ) strRspPath = manApplet->curPath();

    QString strFileName = findFile( this, JS_FILE_TYPE_TXT, strRspPath );
    if( strFileName.length() > 0 )
    {
        mECCReqPathText->setText( strFileName );
    }
}

void CAVPDlg::clickRSAFind()
{
    QString strRspPath = mRSAReqPathText->text();
    if( strRspPath.length() < 1 ) strRspPath = manApplet->curPath();

    QString strFileName = findFile( this, JS_FILE_TYPE_TXT, strRspPath );
    if( strFileName.length() > 0 )
    {
        mRSAReqPathText->setText( strFileName );
    }
}

int CAVPDlg::makeRSA_ES_DET( const QString strPri, const QString strC )
{
    int ret = 0;
    BIN binC = {0,0};
    BIN binM = {0,0};
    BIN binPri = {0,0};

    JS_BIN_decodeHex( strPri.toStdString().c_str(), &binPri );
    JS_BIN_decodeHex( strC.toStdString().c_str(), &binC );

    /* need to set private key */

    ret = JS_PKI_RSADecryptWithPri( JS_PKI_RSA_PADDING_V21, &binC, &binPri, &binM );
    if( ret != 0 ) goto end;


    logRsp( QString( "C = %1").arg(getHexString( binC.pVal, binC.nLen )));
    logRsp( QString( "M = %1").arg(getHexString( binM.pVal, binM.nLen)));
    logRsp( "" );

end :
    JS_BIN_reset( &binC );
    JS_BIN_reset( &binM );
    JS_BIN_reset( &binPri );

    return ret;
}

int CAVPDlg::makeRSA_ES_ENT( int nE, const QString strN, const QString strM )
{
    int ret = 0;
    BIN binM = {0,0};
    BIN binC = {0,0};
    BIN binPub = {0,0};
    BIN binN = {0,0};
    BIN binE = {0,0};

    JS_BIN_decodeHex( strN.toStdString().c_str(), &binN );
    JS_BIN_decodeHex( strM.toStdString().c_str(), &binM );

    /* need to set public key */
    JS_BIN_intToBin( nE, &binE );
    JS_BIN_trimLeft( 0x00, &binE );
    JS_PKI_encodeRSAPublicKeyValue( &binN, &binE, &binPub );

    ret = JS_PKI_RSAEncryptWithPub( JS_PKI_RSA_PADDING_V21, &binM, &binPub, &binC );
    if( ret != 0 ) goto end;

    logRsp( QString( "M = %1").arg(getHexString( binM.pVal, binM.nLen )));
    logRsp( QString( "C = %1").arg(getHexString( binC.pVal, binC.nLen )));
    logRsp( "" );

end :
    JS_BIN_reset( &binM );
    JS_BIN_reset( &binC );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binE );
    JS_BIN_reset( &binN );

    return ret;
}

int CAVPDlg::makeRSA_ES_KGT( int nKeyLen, int nE, int nCount )
{
    int ret = 0;

    BIN binPub = {0,0};
    BIN binPri = {0,0};
    JRSAKeyVal sKeyVal;

    for( int i = 0; i < nCount; i++ )
    {
        JS_BIN_reset( &binPub );
        JS_BIN_reset( &binPri );

        memset( &sKeyVal, 0x00, sizeof(sKeyVal));

        ret = JS_PKI_RSAGenKeyPair( nKeyLen, nE, &binPub, &binPri );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getRSAKeyVal( &binPri, &sKeyVal );
        if( ret != 0 ) goto end;

        logRsp( QString( "n = %1").arg( sKeyVal.pN));
        logRsp( QString( "e = %1").arg( nE ));
        logRsp( QString( "q = %1").arg( sKeyVal.pQ ));
        logRsp( QString( "p = %1").arg( sKeyVal.pP ));
        logRsp( QString( "d = %1").arg( sKeyVal.pD ));
        logRsp( "" );

        JS_PKI_resetRSAKeyVal( &sKeyVal );
    }

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );

    JS_PKI_resetRSAKeyVal( &sKeyVal );

    return ret;
}

int CAVPDlg::makeRSA_PSS_KPG( int nLen, int nE, int nCount )
{
    int ret = 0;

    BIN binPub = {0,0};
    BIN binPri = {0,0};
    JRSAKeyVal sKeyVal;


    for( int i = 0; i < nCount; i++ )
    {
        JS_BIN_reset( &binPub );
        JS_BIN_reset( &binPri );
        memset( &sKeyVal, 0x00, sizeof(sKeyVal));

        ret = JS_PKI_RSAGenKeyPair( nLen, nE, &binPub, &binPri );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getRSAKeyVal( &binPri, &sKeyVal );
        if( ret != 0 ) goto end;

        logRsp( QString( "e = %1").arg( nE ));
        logRsp( QString( "p1 = %1").arg( sKeyVal.pP));
        logRsp( QString( "p2 = %1").arg( sKeyVal.pQ));
        logRsp( QString( "n = %1").arg( sKeyVal.pN ));
        logRsp( QString( "s = %1").arg( sKeyVal.pD));
        logRsp( "" );
    }

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
    JS_PKI_resetRSAKeyVal( &sKeyVal );

    return ret;
}

int CAVPDlg::makeRSA_PSS_SGT( int nE, const QString strPri, const QString strHash, const QString strM )
{
    int ret = 0;
    BIN binM = {0,0};
    BIN binS = {0,0};
    BIN binPri = {0,0};
    //    BIN binPub = {0,0};


    JS_BIN_decodeHex( strM.toStdString().c_str(), &binM );
    JS_BIN_decodeHex( strPri.toStdString().c_str(), &binPri );

    //    ret = JS_PKI_RSAGenKeyPair( 2048, nE, &binPub, &binPri );
    //    if( ret != 0 ) goto end;

    ret = JS_PKI_RSAMakeSign( strHash.toStdString().c_str(), JS_PKI_RSA_PADDING_V21, &binM, &binPri, &binS );
    if( ret != 0 ) goto end;

    logRsp( QString( "M = %1").arg( getHexString(binM.pVal, binM.nLen)));
    logRsp( QString( "S = %1").arg(getHexString(binS.pVal, binS.nLen)));
    logRsp( "" );

end :
    JS_BIN_reset( &binM );
    JS_BIN_reset( &binS );
    JS_BIN_reset( &binPri );
    //    JS_BIN_reset( &binPub );

    return ret;
}

int CAVPDlg::makeRSA_PSS_SVT( int nE, const QString strN, const QString strHash, const QString strM, const QString strS )
{
    int ret = 0;
    BIN binM = {0,0};
    BIN binS = {0,0};
    BIN binPub = {0,0};
    BIN binE = {0,0};
    QString strE;

    JRSAKeyVal sKeyVal;

    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    JS_BIN_intToBin( nE, &binE );
    JS_BIN_trimLeft( 0x00, &binE );
    strE = getHexString( &binE );

    JS_PKI_setRSAKeyVal( &sKeyVal, strN.toStdString().c_str(), strE.toStdString().c_str(), NULL, NULL, NULL, NULL, NULL, NULL );

    JS_BIN_decodeHex( strM.toStdString().c_str(), &binM );
    JS_BIN_decodeHex( strS.toStdString().c_str(), &binS );

    ret = JS_PKI_encodeRSAPublicKey( &sKeyVal, &binPub );
    if( ret != 0 ) goto end;

    ret = JS_PKI_RSAVerifySign( strHash.toStdString().c_str(), JS_PKI_RSA_PADDING_V21, &binM, &binS, &binPub );

    logRsp( QString( "M = %1").arg( getHexString(binM.pVal, binM.nLen)));
    logRsp( QString( "S = %1").arg(getHexString(binS.pVal, binS.nLen)));

    if( ret == 1 )
        logRsp( "Result = P" );
    else
        logRsp( "Result = F" );

    logRsp( "" );

    ret = 0;
end :
    JS_BIN_reset( &binM );
    JS_BIN_reset( &binS );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binE );
    JS_PKI_resetRSAKeyVal( &sKeyVal );

    return ret;
}

int CAVPDlg::makeECDH_KPG( const QString strParam, int nCount )
{
    int ret = 0;

    JECKeyVal sKeyVal;

    BIN binPub = {0,0};
    BIN binPri = {0,0};

    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    for( int i = 0; i < nCount; i++ )
    {
        JS_BIN_reset( &binPri );
        JS_BIN_reset( &binPub );
        JS_PKI_resetECKeyVal( &sKeyVal );

        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getECKeyVal( &binPri, &sKeyVal );
        if( ret != 0 ) goto end;

        logRsp( QString( "d = %1").arg( sKeyVal.pPrivate));
        logRsp( QString( "Qx = %1").arg( getHexString( &binPub.pVal[1], binPub.nLen/2) ));
        logRsp( QString( "Qy = %1").arg( getHexString( &binPub.pVal[binPub.nLen/2+1], binPub.nLen/2)));
        logRsp( "" );

        if( ret != 0 ) goto end;
    }

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_PKI_resetECKeyVal( &sKeyVal );

    return ret;
}

int CAVPDlg::makeECDH_PKV( const QString strParam, const QString strPubX, const QString strPubY )
{
    int ret = 0;

    BIN binPubX = {0,0};
    BIN binPubY = {0,0};

    JS_BIN_decodeHex( strPubX.toStdString().c_str(), &binPubX );
    JS_BIN_decodeHex( strPubY.toStdString().c_str(), &binPubY );

    logRsp( QString( "Qx = %1" ).arg( strPubX ));
    logRsp( QString( "Qy = %1").arg( strPubY));

    ret = JS_PKI_IsValidECCPubKey( strParam.toStdString().c_str(), &binPubX, &binPubY );

    if( ret == 1 )
        logRsp( "Result = P" );
    else
        logRsp( "Result = F" );

    logRsp( "" );
    ret = 0;

end :
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );

    return ret;
}

int CAVPDlg::makeECDH_KAKAT( const QString strParam, const QString strRA, const QString strRB, const QString strKTA1X, const QString strKTA1Y )
{
    int ret = 0;

    BIN binRA = {0,0};
    BIN binRB = {0,0};
    BIN binKTA1X = {0,0};
    BIN binKTA1Y = {0,0};

    BIN binPubX = {0,0};
    BIN binPubY = {0,0};
    BIN binSecX = {0,0};
    BIN binSecY = {0,0};

    JS_BIN_decodeHex( strRA.toStdString().c_str(), &binRA );
    JS_BIN_decodeHex( strRB.toStdString().c_str(), &binRB );
    JS_BIN_decodeHex( strKTA1X.toStdString().c_str(), &binKTA1X );
    JS_BIN_decodeHex( strKTA1Y.toStdString().c_str(), &binKTA1Y );

    ret = JS_PKI_genECPubKey( strParam.toStdString().c_str(), &binRA, &binPubX, &binPubY );
    if( ret != 0 ) goto end;

    //    ret = JS_PKI_getECDHSecretWithValue( "prime256v1", &binRB, &binPubX, &binPubY, &binSecret );
    ret = JS_PKI_getECDHComputeKey( strParam.toStdString().c_str(), &binRB, &binPubX, &binPubY, &binSecX, &binSecY );
    if( ret != 0 ) goto end;

    logRsp( "j = 1" );
    logRsp( QString( "rA = %1").arg( strRA ));
    logRsp( QString( "rB = %1").arg( strRB ));
    logRsp( QString( "KTA1x = %1").arg( strKTA1X ));
    logRsp( QString( "KTA1y = %1").arg( strKTA1Y ));
    logRsp( QString( "KABx = %1").arg(getHexString( binSecX.pVal, binSecX.nLen)));
    logRsp( QString( "KABy = %1").arg(getHexString( binSecY.pVal, binSecY.nLen)));
    logRsp( "" );

end :
    JS_BIN_reset( &binRA );
    JS_BIN_reset( &binRB );
    JS_BIN_reset( &binKTA1X );
    JS_BIN_reset( &binKTA1Y );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );
    JS_BIN_reset( &binSecX );
    JS_BIN_reset( &binSecY );

    return ret;
}

int CAVPDlg::makeECDSA_KPG( const QString strParam, int nNum )
{
    int ret = 0;

    BIN binPri = {0,0};
    BIN binPub = {0,0};
    JECKeyVal sKeyVal;
    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    for( int i = 0; i < nNum; i++ )
    {
        JS_PKI_resetECKeyVal( &sKeyVal );
        JS_BIN_reset( &binPri );
        JS_BIN_reset( &binPub );

        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getECKeyVal( &binPri, &sKeyVal );
        if( ret != 0 ) goto end;

        logRsp( QString( "X = %1").arg( sKeyVal.pPrivate ));
        logRsp( QString( "Yx = %1").arg( sKeyVal.pPubX ));
        logRsp( QString( "Yy = %1").arg( sKeyVal.pPubY ));
        logRsp( "" );
    }

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
    JS_PKI_resetECKeyVal( &sKeyVal );

    return ret;
}

int CAVPDlg::makeECDSA_PKV( const QString strParam, const QString strYX, const QString strYY )
{
    int ret = 0;

    BIN binPubX = {0,0};
    BIN binPubY = {0,0};

    JS_BIN_decodeHex( strYX.toStdString().c_str(), &binPubX );
    JS_BIN_decodeHex( strYY.toStdString().c_str(), &binPubY );

    ret = JS_PKI_IsValidECCPubKey( strParam.toStdString().c_str(), &binPubX, &binPubY );

    logRsp( QString( "Yx = %1" ).arg( strYX ));
    logRsp( QString( "Yy = %1").arg( strYY ));

    if( ret == 1 )
        logRsp( "Result = P" );
    else
        logRsp( "Result = F" );

    logRsp( "" );

end:
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );
    return 0;
}

int CAVPDlg::makeECDSA_SGT( const QString strParam, const QString strHash, const QString strM )
{
    int ret = 0;

    BIN binPub = {0,0};
    BIN binPri = {0,0};
    BIN binM = {0,0};
    BIN binSign = {0,0};
    BIN binSignR = {0,0};
    BIN binSignS = {0,0};

    JECKeyVal   sKeyVal;

    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    JS_BIN_decodeHex( strM.toStdString().c_str(), &binM );

    ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
    if( ret != 0 ) goto end;

    ret = JS_PKI_getECKeyVal( &binPri, &sKeyVal );
    if( ret != 0 ) goto end;

    ret = JS_PKI_ECCMakeSign( strHash.toStdString().c_str(), &binM, &binPri, &binSign );
    if( ret != 0 ) goto end;

    ret = JS_PKI_ECCSignValue( &binSign, &binSignR, &binSignS );
    if( ret != 0 ) goto end;

    logRsp( QString( "M = %1").arg( strM ));
    logRsp( QString( "Yx = %1").arg( sKeyVal.pPubX ));
    logRsp( QString( "Yy = %1").arg( sKeyVal.pPubY ));
    logRsp( QString( "R = %1").arg(getHexString(binSignR.pVal, binSignR.nLen)));
    logRsp( QString( "S = %1").arg(getHexString(binSignS.pVal, binSignS.nLen)));
    logRsp( "" );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binM );
    JS_BIN_reset( &binSign );
    JS_BIN_reset( &binSignR );
    JS_BIN_reset( &binSignS );

    JS_PKI_resetECKeyVal( &sKeyVal );

    return ret;
}

int CAVPDlg::makeECDSA_SVT( const QString strParam, const QString strHash, const QString strM, const QString strYX, const QString strYY, const QString strR, const QString strS )
{
    int ret = 0;

    BIN binPub = {0,0};
    BIN binPubX = {0,0};
    BIN binPubY = {0,0};
    BIN binSign = {0,0};
    BIN binSignR = {0,0};
    BIN binSignS = {0,0};
    BIN binM = {0,0};

    JS_BIN_decodeHex( strM.toStdString().c_str(), &binM );
    JS_BIN_decodeHex( strYX.toStdString().c_str(), &binPubX );
    JS_BIN_decodeHex( strYY.toStdString().c_str(), &binPubY );
    JS_BIN_decodeHex( strR.toStdString().c_str(), &binSignR );
    JS_BIN_decodeHex( strS.toStdString().c_str(), &binSignS );

    ret = JS_PKI_encodeECPublicKeyValue( strParam.toStdString().c_str(), &binPubX, &binPubY, &binPub );
    if( ret != 0 ) goto end;

    ret = JS_PKI_ECCEncodeSignValue( &binSignR, &binSignS, &binSign );
    if( ret != 0 ) goto end;

    ret = JS_PKI_ECCVerifySign( strHash.toStdString().c_str(), &binM, &binSign, &binPub );

    logRsp( QString( "M = %1").arg( strM ));
    logRsp( QString( "Yx = %1").arg( strYX));
    logRsp( QString( "Yy = %1").arg( strYY ));
    logRsp( QString( "R = %1" ).arg( strR ));
    logRsp( QString( "S = %1").arg( strS ));

    if( ret == 1 )
        logRsp( "Result = P" );
    else
        logRsp( "Result = F" );


    logRsp( "" );
    ret = 0;

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );
    JS_BIN_reset( &binSign );
    JS_BIN_reset( &binSignR );
    JS_BIN_reset( &binSignS );
    JS_BIN_reset( &binM );

    return ret;
}
