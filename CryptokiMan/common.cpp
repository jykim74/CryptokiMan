/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "js_pki.h"
#include "js_pki_ext.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_http.h"

#include <QFileDialog>
#include <QDate>
#include <QRegularExpression>
#include <QProcess>
#include <QNetworkInterface>

#include "common.h"
#include "man_tree_item.h"

const QString GetSystemID()
{
    QString strID;

#ifdef Q_OS_MACOS
    QProcess proc;
    QStringList args;
    args << "-c" << "ioreg -rd1 -c IOPlatformExpertDevice |  awk '/IOPlatformSerialNumber/ { print $3; }'";
    proc.start( "/bin/bash", args );
    proc.waitForFinished();
    QString uID = proc.readAll();
    uID.replace( "\"", "" );

    strID = uID.trimmed();
#else

    foreach( QNetworkInterface netIFT, QNetworkInterface::allInterfaces() )
    {
        if( !(netIFT.flags() & QNetworkInterface::IsLoopBack) )
        {
            if( netIFT.flags() & QNetworkInterface::IsUp )
            {
                if( netIFT.flags() & QNetworkInterface::Ethernet || netIFT.flags() & QNetworkInterface::Wifi )
                {
                    if( strID.isEmpty() )
                        strID = netIFT.hardwareAddress();
                    else
                    {
                        strID += QString( "|%1" ).arg( netIFT.hardwareAddress() );
                    }
                }
            }
        }
    }
#endif

    return strID;
}



void getQDateToCKDate( const QDate date, CK_DATE *pCKDate )
{
    if( pCKDate == NULL ) return;

    char    sYear[5];
    char    sMonth[3];
    char    sDay[3];

    memset( sYear, 0x00, sizeof(sYear));
    memset( sMonth, 0x00, sizeof(sMonth));
    memset( sDay, 0x00, sizeof(sDay));

    sprintf( sYear, "%04d", date.year() );
    sprintf( sMonth, "%02d", date.month() );
    sprintf( sDay, "%02d", date.day() );

    memcpy( pCKDate->year, sYear, 4 );
    memcpy( pCKDate->month, sMonth, 2 );
    memcpy( pCKDate->day, sDay, 2 );
}

void getCKDateToQDate( const CK_DATE *pCKDate, QDate *pQDate )
{
    if( pCKDate == NULL || pQDate == NULL ) return;

    char    sYear[5];
    char    sMonth[3];
    char    sDay[3];

    memset( sYear, 0x00, sizeof(sYear));
    memset( sMonth, 0x00, sizeof(sMonth));
    memset( sDay, 0x00, sizeof(sDay));

    memcpy( sYear, pCKDate->year, 4 );
    memcpy( sMonth, pCKDate->month, 2 );
    memcpy( sDay, pCKDate->day, 2 );

    pQDate->setDate( atoi(sYear), atoi(sMonth), atoi(sDay));
}

QString getBool( const BIN *pBin )
{
    QString strOut = "";
    if( pBin == NULL ) return "None";


    if( pBin->nLen == 0 )
        strOut = "None";
    else if( pBin->nLen > 1 )
        strOut = "Invalid";
    else
    {
        if( pBin->pVal[0] == 0x00 )
            strOut = "FALSE";
        else
            strOut = "TRUE";
    }

    return strOut;
}

QString getHexString( const BIN *pBin )
{
    char *pHex = NULL;

    if( pBin == NULL || pBin->nLen <= 0 ) return "";

    JS_BIN_encodeHex( pBin, &pHex );

    QString strHex = pHex;
    if(pHex) JS_free( pHex );

    return strHex;
}

QString getHexString( unsigned char *pData, int nDataLen )
{
    BIN binData = {0,0};
    char *pHex = NULL;
    JS_BIN_set( &binData, pData, nDataLen );
    JS_BIN_encodeHex( &binData, &pHex );

    QString strHex = pHex;

    JS_BIN_reset( &binData );
    if(pHex) JS_free( pHex );

    return strHex;
}

const QString getHexStringArea( unsigned char *pData, int nDataLen, int nWidth  )
{
    QString strMsg = getHexString( pData, nDataLen );

    return getHexStringArea( strMsg, nWidth );
}

const QString getHexStringArea( const BIN *pData, int nWidth )
{
    QString strMsg = getHexString( pData );

    return getHexStringArea( strMsg, nWidth );
}

const QString getHexStringArea( const QString strMsg, int nWidth )
{
    int nBlock = 0;
    int nPos = 0;
    QString strAreaMsg = nullptr;

    int nLen = strMsg.length();
    if( nWidth <= 0 ) return strMsg;

    while( nLen > 0 )
    {
        if( nLen >= nWidth )
            nBlock = nWidth;
        else
            nBlock = nLen;

        strAreaMsg += strMsg.mid( nPos, nBlock );

        nLen -= nBlock;
        nPos += nBlock;

        if( nLen > 0 ) strAreaMsg += "\n";
    }

    return strAreaMsg;
}

static int _getKeyUsage( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    int     nKeyUsage = 0;

    ret = JS_PKI_getKeyUsageValue( pBinExt, &nKeyUsage );

    if( nKeyUsage & JS_PKI_KEYUSAGE_DIGITAL_SIGNATURE )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "DigitalSignature";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_NON_REPUDIATION )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "NonRepudiation";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_KEY_ENCIPHERMENT )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "KeyEncipherment";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_DATA_ENCIPHERMENT )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "DataEncipherment";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_KEY_AGREEMENT )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "KeyAgreement";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_CERT_SIGN )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "keyCertSign";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_CRL_SIGN )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "cRLSign";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_ENCIPHER_ONLY )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "EncipherOnly";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_DECIPHER_ONLY )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "DecipherOnly";
    }

    return 0;
}

static int _getCRLNum( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    char    *pCRLNum = NULL;

    ret = JS_PKI_getCRLNumberValue( pBinExt, &pCRLNum );

    if( pCRLNum ) {
        if(bShow)
            strVal = QString( "CRL Number=%1" ).arg( pCRLNum );
        else
            strVal = pCRLNum;

        JS_free( pCRLNum );
    }

    return 0;
}

static int _getCertPolicy( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int i = 0;
    JExtPolicyList *pPolicyList = NULL;
    JExtPolicyList *pCurList = NULL;

    ret = JS_PKI_getCertificatePoliciesValue( pBinExt, &pPolicyList );

    pCurList = pPolicyList;

    while( pCurList )
    {
        if( bShow )
        {
            strVal += QString( "[%1]Certificate Policy:\n" ).arg(i+1);
            strVal += QString( " Policy Identifier=%1\n" ).arg( pCurList->sPolicy.pOID );
            if( pCurList->sPolicy.pCPS )
            {
                strVal += QString( " [%1,1] CPS = %2\n" ).arg( i+1 ).arg( pCurList->sPolicy.pCPS );
            }

            if( pCurList->sPolicy.pUserNotice )
            {
                strVal += QString( " [%1,2] UserNotice = %2\n" ).arg( i+1 ).arg( pCurList->sPolicy.pUserNotice );
            }
        }
        else
        {
            if( strVal.length() > 0 ) strVal += "%%";

            strVal += QString("#OID$%1#CPS$%2#UserNotice$%3")
                .arg( pCurList->sPolicy.pOID )
                .arg( pCurList->sPolicy.pCPS )
                .arg( pCurList->sPolicy.pUserNotice );
        }

        pCurList = pCurList->pNext;
        i++;
    }

    if( pPolicyList ) JS_PKI_resetExtPolicyList( &pPolicyList );
    return 0;
}


static int _getSKI( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    char        *pSKI = NULL;

    ret = JS_PKI_getSubjectKeyIdentifierValue( pBinExt, &pSKI );

    if( pSKI )
    {
        strVal = pSKI;
        JS_free( pSKI );
    }

    return 0;
}


static int _getAKI( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    char    *pAKI = NULL;
    char    *pIssuer = NULL;
    char    *pSerial = NULL;

    ret = JS_PKI_getAuthorityKeyIdentifierValue( pBinExt, &pAKI, &pIssuer, &pSerial );

    if( bShow == true )
    {
        strVal = QString( "KeyID=%1\n").arg( pAKI );
        if( pIssuer ) strVal += QString( "CertificateIssuer=\n    %1\n").arg( pIssuer );
        if( pSerial ) strVal += QString( "CertificateSerialNumber=%1").arg( pSerial );
    }
    else
    {
        strVal = QString( "KEYID$%1#ISSUER$%2#SERIAL$%3").arg( pAKI ).arg( pIssuer ).arg( pSerial );
    }

    if( pAKI ) JS_free( pAKI );
    if( pIssuer ) JS_free( pIssuer );
    if( pSerial ) JS_free( pSerial );

    return 0;
}

static int _getEKU( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    JStrList   *pEKUList = NULL;
    JStrList   *pCurList = NULL;

    ret = JS_PKI_getExtendedKeyUsageValue( pBinExt, &pEKUList );

    pCurList = pEKUList;

    while( pCurList )
    {
        if( strVal.length() > 0 ) strVal += ",";

        strVal += QString( pCurList->pStr );

        pCurList = pCurList->pNext;
    }

    if( pEKUList ) JS_UTIL_resetStrList( &pEKUList );
    return 0;
}

static int _getCRLDP( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    int i = 1;
    JNameValList   *pCRLDPList = NULL;
    JNameValList    *pCurList = NULL;

    ret = JS_PKI_getCRLDPValue( pBinExt, &pCRLDPList );

    pCurList = pCRLDPList;

    while( pCurList )
    {
        if( bShow )
        {
            strVal += QString( "[%1] CRL Distribution Point\n" ).arg(i);
            strVal += QString( " %1=%2\n" ).arg( pCurList->sNameVal.pName ).arg( pCurList->sNameVal.pValue );
        }
        else
        {
            if( strVal.length() > 0 ) strVal += "#";

            strVal += QString( "%1$%2")
                .arg( pCurList->sNameVal.pName )
                .arg( pCurList->sNameVal.pValue );
        }

        pCurList = pCurList->pNext;
        i++;
    }

    if( pCRLDPList ) JS_UTIL_resetNameValList( &pCRLDPList );
    return 0;
}

static int _getBC( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int nType = -1;
    int nPathLen = -1;

    QString strType;
    QString strPathLen;

    ret = JS_PKI_getBCValue( pBinExt, &nType, &nPathLen );

    if( nType == JS_PKI_BC_TYPE_CA )
        strType = "CA";
    else if( nType == JS_PKI_BC_TYPE_USER )
        strType = "EE";


    if( nPathLen >= 0 )
        strPathLen = QString("$PathLen:%1").arg( nPathLen );

    if( bShow )
    {
        strVal = QString( "SubjectType=%1\n").arg(strType);
        if( nPathLen >= 0 )
            strVal += QString( "PathLengthConstraint=%1" ).arg(nPathLen);
        else
        {
            if( strType == "CA" )
                strVal += QString( "PathLengthConstraint=None" );
        }
    }
    else
    {
        strVal += strType;
        strVal += strPathLen;
    }

    return 0;
}


static int _getPC( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int nREP = -1;
    int nIPM = -1;

    ret = JS_PKI_getPolicyConstValue( pBinExt, &nREP, &nIPM );

    if( bShow )
    {
        if( nREP >= 0 ) strVal += QString("RequiredExplicitPolicySkipCerts=%1\n").arg( nREP );
        if( nIPM >= 0 ) strVal += QString("InhibitPolicyMappingSkipCerts=%1\n").arg( nIPM );
    }
    else
    {
        if( nREP >= 0 ) strVal += QString("#REP$%1").arg( nREP );
        if( nIPM >= 0 ) strVal += QString("#IPM$%1").arg( nIPM );
    }

    return 0;
}

static int _getAIA( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int i = 1;
    JExtAuthorityInfoAccessList    *pAIAList = NULL;
    JExtAuthorityInfoAccessList    *pCurList = NULL;

    ret = JS_PKI_getAuthorityInfoAccessValue( pBinExt, &pAIAList );

    pCurList = pAIAList;

    while( pCurList )
    {
        QString strType;
        strType = JS_PKI_getGenNameString( pCurList->sAuthorityInfoAccess.nType );

        if( bShow )
        {
            strVal += QString( "[%1]Authority Info Access\n" ).arg(i);
            strVal += QString( " Access Method=%1\n").arg(pCurList->sAuthorityInfoAccess.pMethod);
            strVal += QString( " Alternative Name:\n" );
            strVal += QString( " %1=%2\n" ).arg(strType).arg(pCurList->sAuthorityInfoAccess.pName );
        }
        else
        {
            if( strVal.length() > 0 ) strVal += "%%";

            strVal += QString( "Method$%1#Type$%2#Name$%3")
                .arg( pCurList->sAuthorityInfoAccess.pMethod )
                .arg( strType )
                .arg( pCurList->sAuthorityInfoAccess.pName );
        }

        pCurList = pCurList->pNext;
        i++;
    }

    if( pAIAList ) JS_PKI_resetExtAuthorityInfoAccessList( &pAIAList );
    return 0;
}

static int _getIDP( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int i = 1;

    JNumValList    *pIDPList = NULL;
    JNumValList    *pCurList = NULL;

    ret = JS_PKI_getIssuingDistPointValue( pBinExt, &pIDPList );

    pCurList = pIDPList;

    while( pCurList )
    {
        QString strType;
        strType = JS_PKI_getGenNameString( pCurList->sNumVal.nNum );

        if( bShow )
        {
            strVal += QString("[%1] Issuing Distribution Point:\n" ).arg(i);
            strVal += QString( " %1=%2\n" ).arg( strType ).arg( pCurList->sNumVal.pValue );
        }
        else
        {
            strVal += QString( "#%1$%2" ).arg( strType ).arg( pCurList->sNumVal.pValue );
        }

        pCurList = pCurList->pNext;
    }

    if( pIDPList ) JS_UTIL_resetNumValList( &pIDPList );
    return 0;
}

static int _getAltName( const BIN *pBinExt, int nNid, bool bShow, QString& strVal )
{
    int     ret = 0;
    JNumValList    *pAltNameList = NULL;
    JNumValList    *pCurList = NULL;

    ret = JS_PKI_getAlternativNameValue( pBinExt, &pAltNameList );

    pCurList = pAltNameList;

    while( pCurList )
    {
        QString strType;
        strType = JS_PKI_getGenNameString( pCurList->sNumVal.nNum );

        if( bShow )
        {
            if( pCurList->sNumVal.nNum == JS_PKI_NAME_TYPE_OTHERNAME )
                strVal += QString( "%1: %2\n").arg( strType ).arg( pCurList->sNumVal.pValue );
            else
                strVal += QString( "%1=%2\n" ).arg( strType ).arg( pCurList->sNumVal.pValue );
        }
        else
        {
            strVal += QString( "#%1$%2").arg( strType ).arg(pCurList->sNumVal.pValue);
        }

        pCurList = pCurList->pNext;
    }

    if( pAltNameList ) JS_UTIL_resetNumValList( &pAltNameList );
    return 0;
}

static int _getPM( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int i = 1;

    JExtPolicyMappingsList *pPMList = NULL;
    JExtPolicyMappingsList *pCurList = NULL;

    ret = JS_PKI_getPolicyMappingsValue( pBinExt, &pPMList );

    pCurList = pPMList;

    while( pCurList )
    {
        if( bShow )
        {
            strVal += QString( "[%1]Issuer Domain=%2\n" ).arg(i).arg(pCurList->sPolicyMappings.pIssuerDomainPolicy );
            if( pCurList->sPolicyMappings.pSubjectDomainPolicy )
                strVal += QString( " Subject Domain=%1\n" ).arg( pCurList->sPolicyMappings.pSubjectDomainPolicy );
        }
        else
        {
            if( strVal.length() > 0 ) strVal += "%%";

            strVal += QString( "IDP$%1#SDP$%2")
                .arg( pCurList->sPolicyMappings.pIssuerDomainPolicy )
                .arg( pCurList->sPolicyMappings.pSubjectDomainPolicy );
        }

        pCurList = pCurList->pNext;
        i++;
    }

    if( pPMList ) JS_PKI_resetExtPolicyMappingsList( &pPMList );
    return 0;
}


static int _getNC( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    int     pi = 1;
    int     ei = 1;

    JExtNameConstsList     *pNCList = NULL;
    JExtNameConstsList     *pCurList = NULL;

    ret = JS_PKI_getNameConstraintsValue( pBinExt, &pNCList );

    pCurList = pNCList;

    while( pCurList )
    {
        QString strType = JS_PKI_getGenNameString( pCurList->sNameConsts.nType );

        if( bShow )
        {
            if( pCurList->sNameConsts.nKind == JS_PKI_NAME_CONSTS_KIND_PST )
            {
                if( pi == 1 ) strVal += QString( "Permitted\n" );
                strVal += QString( " [%1]Subtrees(%2..%3)\n" ).arg( pi ).arg( pCurList->sNameConsts.nMax ).arg( pCurList->sNameConsts.nMin );
                strVal += QString( "  %1 : %2\n" ).arg( strType ).arg( pCurList->sNameConsts.pValue );

                pi++;
            }
            else
            {
                if( ei == 1 ) strVal += QString( "Excluded\n" );
                strVal += QString( " [%1]Subtrees(%2..%3)\n" ).arg( ei ).arg( pCurList->sNameConsts.nMax ).arg( pCurList->sNameConsts.nMin );
                strVal += QString( "  %1 : %2\n" ).arg( strType ).arg( pCurList->sNameConsts.pValue );

                ei++;
            }
        }
        else
        {
            strVal += QString("#%1$%2$%3$%4$%5")
                .arg( pCurList->sNameConsts.nKind )
                .arg( pCurList->sNameConsts.nType )
                .arg(pCurList->sNameConsts.pValue )
                .arg(pCurList->sNameConsts.nMin )
                .arg(pCurList->sNameConsts.nMax );
        }

        pCurList = pCurList->pNext;
    }

    return 0;
}

static int _getCRLReason( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    int     nReason = -1;

    ret = JS_PKI_getCRLReasonValue( pBinExt, &nReason );

    if( nReason >= 0 ) strVal = crl_reasons[nReason];

    return 0;
}


void getInfoValue( const JExtensionInfo *pExtInfo, QString& strVal )
{
    int ret = 0;
    QString strSN = pExtInfo->pOID;
    BIN     binExt = {0,0};

    JS_BIN_decodeHex( pExtInfo->pValue, &binExt );

    if( strSN == JS_PKI_ExtNameKeyUsage )
    {
        ret = _getKeyUsage( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLNum )
    {
        ret = _getCRLNum( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePolicy )
    {
        ret = _getCertPolicy( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameSKI )
    {
        ret = _getSKI( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameAKI )
    {
        ret = _getAKI( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameEKU )
    {
        ret = _getEKU( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLDP )
    {
        ret = _getCRLDP( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameBC )
    {
        ret = _getBC( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePC )
    {
        ret = _getPC( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameAIA )
    {
        ret = _getAIA( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameIDP )
    {
        ret = _getIDP( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameSAN || strSN == JS_PKI_ExtNameIAN )
    {
        int nNid = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
        ret = _getAltName( &binExt, nNid, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePM )
    {
        ret = _getPM( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameNC )
    {
        ret = _getNC( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLReason )
    {
        ret = _getCRLReason( &binExt, true, strVal );
    }
    else
    {
        strVal = pExtInfo->pValue;
    }

    JS_BIN_reset( &binExt );
}

int getDataType( int nItemType )
{
    switch ( nItemType ) {
    case HM_ITEM_TYPE_DATA :
        return OBJ_DATA_IDX;

    case HM_ITEM_TYPE_CERTIFICATE:
        return OBJ_CERT_IDX;

    case HM_ITEM_TYPE_PUBLICKEY:
        return OBJ_PUBKEY_IDX;

    case HM_ITEM_TYPE_PRIVATEKEY:
        return OBJ_PRIKEY_IDX;

    case HM_ITEM_TYPE_SECRETKEY:
        return OBJ_SECRET_IDX;

    default:
        return -1;
    }
}

int getDataLen( int nType, const QString strData )
{
    int nLen = 0;
    if( strData.isEmpty() ) return 0;

    QString strMsg = strData;

    if( nType == DATA_HEX )
    {
        strMsg.remove( QRegularExpression("[\t\r\n\\s]") );
    }
    else if( nType == DATA_BASE64 )
    {
        strMsg.remove( QRegularExpression( "-----BEGIN [^-]+-----") );
        strMsg.remove( QRegularExpression("-----END [^-]+-----") );
        strMsg.remove( QRegularExpression("[\t\r\n\\s]") );
    }

    if( nType == DATA_HEX )
    {
        if( isHex( strMsg ) == false ) return -1;
        if( strMsg.length() % 2 ) return -2;

        nLen = strMsg.length() / 2;
    }
    else if( nType == DATA_BASE64 )
    {
        if( isBase64( strMsg ) == false ) return -1;

        BIN bin = {0,0};
        JS_BIN_decodeBase64( strMsg.toStdString().c_str(), &bin );
        nLen = bin.nLen;
        JS_BIN_reset( &bin );
    }
    else if( nType == DATA_URL )
    {
        char *pURL = NULL;
        if( isURLEncode( strMsg ) == false ) return -1;

        JS_BIN_decodeURL( strMsg.toStdString().c_str(), &pURL );
        if( pURL )
        {
            nLen = strlen( pURL );
            JS_free( pURL );
        }
    }
    else
    {
        nLen = strData.toUtf8().length();
    }

    return nLen;
}

int getDataLen( const QString strType, const QString strData )
{
    int nType = DATA_STRING;

    QString strLower = strType.toLower();

    if( strLower == "hex" )
        nType = DATA_HEX;
    else if( strLower == "base64" )
        nType = DATA_BASE64;
    else if( strLower == "url" )
        nType = DATA_URL;

    return getDataLen( nType, strData );
}

const QString getDataLenString( int nType, const QString strData )
{
    int nLen = 0;
    if( strData.isEmpty() ) return 0;

    QString strMsg = strData;
    QString strLen;

    if( nType == DATA_HEX )
    {
        strMsg.remove( QRegularExpression("[\t\r\n\\s]") );
    }
    else if( nType == DATA_BASE64 )
    {
        strMsg.remove( QRegularExpression( "-----BEGIN [^-]+-----") );
        strMsg.remove( QRegularExpression("-----END [^-]+-----") );
        strMsg.remove( QRegularExpression("[\t\r\n\\s]") );
    }

    if( nType == DATA_HEX )
    {
        if( isHex( strMsg ) == false )
        {
            strLen = QString( "-1" );
            return strLen;
        }

        nLen = strMsg.length() / 2;

        if( strMsg.length() % 2 )
        {
            nLen++;
            strLen = QString( "_%1" ).arg( nLen );
        }
        else
        {
            strLen = QString( "%1" ).arg( nLen );
        }
    }
    else if( nType == DATA_BASE64 )
    {
        if( isBase64( strMsg ) == false )
        {
            strLen = QString( "-1" );
            return strLen;
        }

        BIN bin = {0,0};
        JS_BIN_decodeBase64( strMsg.toStdString().c_str(), &bin );
        nLen = bin.nLen;
        JS_BIN_reset( &bin );

        strLen = QString( "%1" ).arg( nLen );
    }
    else if( nType == DATA_URL )
    {
        if( isURLEncode( strMsg ) == false )
        {
            strLen = QString( "-1" );
            return strLen;
        }

        char *pURL = NULL;
        JS_BIN_decodeURL( strMsg.toStdString().c_str(), &pURL );
        if( pURL )
        {
            nLen = strlen( pURL );
            JS_free( pURL );
        }

        strLen = QString( "%1" ).arg( nLen );
    }
    else
    {
        strLen = QString( "%1" ).arg( strMsg.toUtf8().length() );
    }

    return strLen;
}

const QString getDataLenString( const QString strType, const QString strData )
{
    int nType = DATA_STRING;

    QString strLower = strType.toLower();

    if( strLower == "hex" )
        nType = DATA_HEX;
    else if( strLower == "base64" )
        nType = DATA_BASE64;
    else if( strLower == "url" )
        nType = DATA_URL;

    return getDataLenString( nType, strData );
}

void getBINFromString( BIN *pBin, const QString& strType, const QString& strString )
{
    int nType = 0;

    if( strType.toUpper() == "HEX" )
        nType = DATA_HEX;
    else if( strType.toUpper() == "BASE64" )
        nType = DATA_BASE64;
    else if( strType.toUpper() == "URL" )
        nType = DATA_URL;
    else
        nType = DATA_STRING;

    getBINFromString( pBin, nType, strString );
}

void getBINFromString( BIN *pBin, int nType, const QString& strString )
{
    QString srcString = strString;

    if( pBin == NULL ) return;

    if( nType == DATA_HEX )
    {
        srcString.remove( QRegularExpression("[\t\r\n\\s]") );
        if( isHex( srcString ) == false ) return;

        JS_BIN_decodeHex( srcString.toStdString().c_str(), pBin );
    }
    else if( nType == DATA_BASE64 )
    {
        srcString.remove( QRegularExpression( "-----BEGIN [^-]+-----") );
        srcString.remove( QRegularExpression("-----END [^-]+-----") );
        srcString.remove( QRegularExpression("[\t\r\n\\s]") );
        if( isBase64( srcString ) == false ) return;

        JS_BIN_decodeBase64( srcString.toStdString().c_str(), pBin );
    }
    else if( nType == DATA_URL )
    {
        char *pStr = NULL;
        if( isURLEncode( srcString ) == false ) return;

        JS_BIN_decodeURL( srcString.toStdString().c_str(), &pStr );

        if( pStr )
        {
            JS_BIN_set( pBin, (unsigned char *)pStr, strlen(pStr));
            JS_free( pStr );
        }
    }
    else
    {
        JS_BIN_set( pBin, (unsigned char *)srcString.toStdString().c_str(), srcString.toUtf8().length() );
    }
}

QString getStringFromBIN( const BIN *pBin, const QString& strType, bool bSeenOnly )
{
    int nType = 0;

    if( strType.toUpper() == "HEX" )
        nType = DATA_HEX;
    else if( strType.toUpper() == "BASE64" )
        nType = DATA_BASE64;
    else if( strType.toUpper() == "URL" )
        nType = DATA_URL;
    else
        nType = DATA_STRING;

    return getStringFromBIN( pBin, nType, bSeenOnly );
}

static char _getch( unsigned char c )
{
    if( isprint(c) )
        return c;
    else {
        return '.';
    }
}

QString getStringFromBIN( const BIN *pBin, int nType, bool bSeenOnly )
{
    QString strOut;
    char *pOut = NULL;

    if( pBin == NULL || pBin->nLen <= 0 ) return "";

    if( nType == DATA_HEX )
    {
        JS_BIN_encodeHex( pBin, &pOut );
        strOut = pOut;
    }
    else if( nType == DATA_BASE64 )
    {
        JS_BIN_encodeBase64( pBin, &pOut );
        strOut = pOut;
    }
    else if( nType == DATA_URL )
    {
        char *pStr = NULL;
        JS_BIN_string( pBin, &pStr );
        JS_BIN_encodeURL( pStr, &pOut );
        strOut = pOut;
        if( pStr ) JS_free( pStr );
    }
    else
    {
        int i = 0;

        if( bSeenOnly )
        {
            if( pBin->nLen > 0 )
            {
                pOut = (char *)JS_malloc(pBin->nLen + 1);

                for( i=0; i < pBin->nLen; i++ )
                    pOut[i] = _getch( pBin->pVal[i] );

                pOut[i] = 0x00;
            }
        }
        else
        {
            JS_BIN_string( pBin, &pOut );
        }

        strOut = pOut;
    }

    if( pOut ) JS_free( pOut );
    return strOut;
}

QString getMechFlagString( unsigned long uFlag )
{
    QString strFlag = QString( "0x%1" ).arg( uFlag, -8, 16, QLatin1Char( ' ' ) );

    if( uFlag & CKF_DECRYPT ) strFlag += " | Decrypt";
    if( uFlag & CKF_DERIVE ) strFlag += " | Derive";
    if( uFlag & CKF_DIGEST ) strFlag += " | Digest";
    if( uFlag & CKF_ENCRYPT ) strFlag += " | Encrypt";
    if( uFlag & CKF_GENERATE ) strFlag += " | Generate";
    if( uFlag & CKF_GENERATE_KEY_PAIR ) strFlag += " | Generate key pair";
    if( uFlag & CKF_HW ) strFlag += " | HW";
    if( uFlag & CKF_SIGN ) strFlag += " | Sign";
    if( uFlag & CKF_VERIFY ) strFlag += " | Verify";
    if( uFlag & CKF_WRAP ) strFlag += " | Wrap";
    if( uFlag & CKF_UNWRAP ) strFlag += " | Unwrap";
    if( uFlag & CKF_SIGN_RECOVER ) strFlag += " | Sign recover";
    if( uFlag & CKF_VERIFY_RECOVER ) strFlag += " | Verify recover";

    return strFlag;
}

QString getSlotFlagString( unsigned long uFlag )
{
    QString strFlag = QString( "%1" ).arg( uFlag );

    if( uFlag & CKF_TOKEN_PRESENT )
        strFlag += " | token present";

    if( uFlag & CKF_REMOVABLE_DEVICE )
        strFlag += " | removable device";

    if( uFlag & CKF_HW_SLOT )
        strFlag += " | HW slot";

    return strFlag;
}

QString getTokenFlagString( unsigned long uFlag )
{
    QString strFlag = QString( "%1" ).arg( uFlag );

    if( uFlag & CKF_TOKEN_INITIALIZED ) strFlag += " | token initialized";
    if( uFlag & CKF_RNG ) strFlag += " | RNG";
    if( uFlag & CKF_WRITE_PROTECTED ) strFlag += " | write protected";
    if( uFlag & CKF_LOGIN_REQUIRED ) strFlag += " | login required";
    if( uFlag & CKF_USER_PIN_INITIALIZED ) strFlag += " | user pin initialized";
    if( uFlag & CKF_RESTORE_KEY_NOT_NEEDED ) strFlag += " | restore key not needed";
    if( uFlag & CKF_CLOCK_ON_TOKEN ) strFlag += " | clock on token";
    if( uFlag & CKF_PROTECTED_AUTHENTICATION_PATH ) strFlag += " | protected authentication path";
    if( uFlag & CKF_DUAL_CRYPTO_OPERATIONS ) strFlag += " | dual crypto operations";

    return strFlag;
}

QString getSessionFlagString( unsigned long uFlag )
{
    QString strFlag = QString( "%1" ).arg( uFlag );

    if( uFlag & CKF_RW_SESSION ) strFlag += " | CKF_RW_SESSION";
    if( uFlag & CKF_SERIAL_SESSION ) strFlag += " | CKF_SERIAL_SESSION";

    return strFlag;
}

QString getSessionStateString( unsigned long uState )
{
    QString strState = QString( "%1" ).arg( uState );

    if( uState == CKS_RO_PUBLIC_SESSION )
        strState += " | RO_PUBLIC_SESSION";
    else if( uState == CKS_RO_USER_FUNCTIONS)
        strState += " | RO_USER_FUNCTIONS";
    else if( uState == CKS_RW_PUBLIC_SESSION )
        strState += " | RW_PUBLIC_SESSION";
    else if( uState == CKS_RW_SO_FUNCTIONS )
        strState += " | RW_SO_FUNCTIONS";
    else if( uState == CKS_RW_USER_FUNCTIONS )
        strState += " | RW_USER_FUNCTIONS";

    return strState;
}

const QString getItemTypeName( int nType )
{
    switch ( nType ) {
    case HM_ITEM_TYPE_ROOT :
        return "Root";
    case HM_ITEM_TYPE_SLOT :
        return "Slot";
    case HM_ITEM_TYPE_TOKEN :
        return "Token";
    case HM_ITEM_TYPE_MECHANISM :
        return "Mechanism";
    case HM_ITEM_TYPE_SESSION :
        return "Session";
    case HM_ITEM_TYPE_OBJECTS :
        return "Objects";
    case HM_ITEM_TYPE_CERTIFICATE :
        return "Certificate";
    case HM_ITEM_TYPE_PUBLICKEY :
        return "PublicKey";
    case HM_ITEM_TYPE_PRIVATEKEY :
        return "PrivateKey";
    case HM_ITEM_TYPE_SECRETKEY :
        return "SecretKey";
    case HM_ITEM_TYPE_DATA :
        return "Data";
    }

    return "Unknown";
}

bool isEmail( const QString strEmail )
{
    QRegExp mailREX("\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}\\b");
    mailREX.setCaseSensitivity(Qt::CaseInsensitive );

    return mailREX.exactMatch( strEmail );
}

bool isHex( const QString strHexString )
{
    return isValidNumFormat( strHexString, 16 );
}

bool isBase64( const QString strBase64String )
{
    QRegExp base64REX("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$");
    base64REX.setCaseSensitivity(Qt::CaseInsensitive );

    return base64REX.exactMatch( strBase64String );
}

bool isURLEncode( const QString strURLEncode )
{
    QRegExp urlEncodeREX("^(?:[^%]|%[0-9A-Fa-f]{2})+$");
    urlEncodeREX.setCaseSensitivity(Qt::CaseInsensitive );

    return urlEncodeREX.exactMatch( strURLEncode );
}


bool isValidNumFormat( const QString strInput, int nNumber )
{
    QRegExp strReg;

    if( nNumber == 2 )
    {
        strReg.setPattern( "[0-1]+");
    }
    else if( nNumber == 16 )
    {
        strReg.setPattern( "[0-9a-fA-F]+" );
    }
    else
    {
        strReg.setPattern( "[0-9]+" );
    }

    return strReg.exactMatch( strInput );
}

void setAES_GCMParam( const BIN *pIV, const BIN *pAAD, int nReqLen, CK_MECHANISM *pMech )
{
    pMech->mechanism = CKM_AES_GCM;
    CK_GCM_PARAMS *pGCMParam = NULL;

    pGCMParam = (CK_GCM_PARAMS *)JS_calloc( 1, sizeof(CK_GCM_PARAMS));

    pGCMParam->ulIvLen = pIV->nLen;
    pGCMParam->pIv = pIV->pVal;
    pGCMParam->ulAADLen = pAAD->nLen;
    pGCMParam->pAAD = pAAD->pVal;
    pGCMParam->ulIvBits = pIV->nLen * 8;
    pGCMParam->ulTagBits = nReqLen * 8;

    pMech->pParameter = pGCMParam;
    pMech->ulParameterLen = sizeof(CK_GCM_PARAMS);
}

void setAES_CCMParam( const BIN *pIV, const BIN *pAAD, int nSrcLen, int nReqLen, CK_MECHANISM *pMech )
{
    pMech->mechanism = CKM_AES_CCM;
    CK_CCM_PARAMS *pCCMParam = NULL;

    pCCMParam = (CK_CCM_PARAMS *)JS_calloc( 1, sizeof(CK_CCM_PARAMS));
    pCCMParam->ulDataLen = nSrcLen;
    pCCMParam->pNonce = pIV->pVal;
    pCCMParam->ulNonceLen = pIV->nLen;
    pCCMParam->pAAD = pAAD->pVal;
    pCCMParam->ulAADLen = pAAD->nLen;
    pCCMParam->ulMACLen = nReqLen;

    pMech->pParameter = pCCMParam;
    pMech->ulParameterLen = sizeof(CK_CCM_PARAMS);
}

bool isRSA_PSS( int nMech )
{
    switch (nMech) {
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
        return true;
    default:
        return false;
    }

    return false;
}

const QString getMechHex( long uMech )
{
    QString strHex = QString( "%1" ).arg( uMech, 8, 16, QLatin1Char('0') ).toUpper();

    return QString( "0x%1" ).arg( strHex );
}

void getOID( const QString strType, const QString strValue, BIN *pOID )
{
    BIN binVal = {0,0};
    char sOIDText[128];

    memset( sOIDText, 0x00, sizeof(sOIDText));

    if( strValue.length() <= 0 ) return;

    if( strType == "Text" )
    {
        JS_PKI_getOIDFromString( strValue.toStdString().c_str(), pOID );
    }
    else if( strType == "Value Hex" )
    {
        JS_BIN_decodeHex( strValue.toStdString().c_str(), &binVal );
        JS_PKI_getStringFromOIDValue( &binVal, sOIDText );
        JS_PKI_getOIDFromString( sOIDText, pOID );
        JS_BIN_reset( &binVal );
    }
    else if( strType == "ShortName" )
    {
        JS_PKI_getOIDFromSN( strValue.toStdString().c_str(), sOIDText );
        JS_PKI_getOIDFromString( sOIDText, pOID );
    }
    else if( strType == "LongName" )
    {
        JS_PKI_getOIDFromLN( strValue.toStdString().c_str(), sOIDText );
        JS_PKI_getOIDFromString( sOIDText, pOID );
    }
    else
    {
        JS_BIN_decodeHex( strValue.toStdString().c_str(), pOID );
    }

    JS_BIN_reset( &binVal );
}

int writePriKeyPEM( const BIN *pPriKey, const QString strPath )
{
    int nKeyType = -1;
    int nFileType = -1;

    if( pPriKey == NULL ) return -1;

    nKeyType = JS_PKI_getPriKeyType( pPriKey );
    if( nKeyType < 0 ) return -2;

    switch (nKeyType) {
    case JS_PKI_KEY_TYPE_RSA:
        nFileType = JS_PEM_TYPE_RSA_PRIVATE_KEY;
        break;

    case JS_PKI_KEY_TYPE_ECC:
    case JS_PKI_KEY_TYPE_SM2:
        nFileType = JS_PEM_TYPE_EC_PRIVATE_KEY;
        break;

    case JS_PKI_KEY_TYPE_DSA:
        nFileType = JS_PEM_TYPE_DSA_PRIVATE_KEY;
        break;
    default:
        nFileType = JS_PEM_TYPE_PRIVATE_KEY;
        break;
    }

    return JS_BIN_writePEM( pPriKey, nFileType, strPath.toLocal8Bit().toStdString().c_str() );
}

int writePubKeyPEM( const BIN *pPubKey, const QString strPath )
{
    int nKeyType = -1;
    int nFileType = -1;

    if( pPubKey == NULL ) return -1;

    nKeyType = JS_PKI_getPubKeyType( pPubKey );
    if( nKeyType < 0 ) return -2;

    switch (nKeyType) {
    case JS_PKI_KEY_TYPE_RSA:
        nFileType = JS_PEM_TYPE_RSA_PUBLIC_KEY;
        break;

    case JS_PKI_KEY_TYPE_ECC:
    case JS_PKI_KEY_TYPE_SM2:
        nFileType = JS_PEM_TYPE_EC_PUBLIC_KEY;
        break;

    case JS_PKI_KEY_TYPE_DSA:
        nFileType = JS_PEM_TYPE_DSA_PUBLIC_KEY;
        break;
    default:
        nFileType = JS_PEM_TYPE_PUBLIC_KEY;
        break;
    }

    return JS_BIN_writePEM( pPubKey, nFileType, strPath.toLocal8Bit().toStdString().c_str() );
}
