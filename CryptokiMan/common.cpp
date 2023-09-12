#include "js_pki.h"
#include "js_pki_ext.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"

#include <QFileDialog>
#include <QDate>

#include "common.h"
#include "man_tree_item.h"

QString findFile( QWidget *parent, int nType, const QString strPath )
{
    QString strCurPath;

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    if( strPath.length() <= 0 )
        strCurPath = QDir::currentPath();
    else
        strCurPath = strPath;

//    QString strPath = QDir::currentPath();

    QString strType;
    QString selectedFilter;

    if( nType == JS_FILE_TYPE_CERT )
        strType = QObject::tr("Cert Files (*.crt *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_PRIKEY )
        strType = QObject::tr("Key Files (*.key *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_TXT )
        strType = QObject::tr("TXT Files (*.txt *.log);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_BER )
        strType = QObject::tr("BER Files (*.ber *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_BIN )
        strType = QObject::tr("BIN Files (*.bin *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_DLL )
#ifdef WIN32
        strType = QObject::tr( "DLL Files (*.dll);;SO Files (*.so);;All Files (*.*)" );
#else
        strType = QObject::tr( "SO Files (*.so *.dylib);;All Files (*.*)" );
#endif
    else if( nType == JS_FILE_TYPE_PFX )
        strType = QObject::tr("PFX Files (*.pfx *.p12 *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_ALL )
        strType = QObject::tr("All Files(*.*)" );

    QString fileName = QFileDialog::getOpenFileName( parent,
                                                     QObject::tr( "Open File" ),
                                                     strCurPath,
                                                     strType,
                                                     &selectedFilter,
                                                     options );

    return fileName;
};

QString saveFile( QWidget *parent, int nType, const QString strPath )
{
    QString strCurPath;
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strType;

    if( strPath.length() <= 0 )
        strCurPath = QDir::currentPath();
    else
        strCurPath = strPath;

    if( nType == JS_FILE_TYPE_CERT )
        strType = QObject::tr("Cert Files (*.crt *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_PRIKEY )
        strType = QObject::tr("Key Files (*.key *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_TXT )
        strType = QObject::tr("TXT Files (*.txt *.log);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_BER )
        strType = QObject::tr("BER Files (*.ber *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_BIN )
        strType = QObject::tr("BIN Files (*.bin *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_DLL )
        strType = QObject::tr( "DLL Files (*.dll);;SO Files (*.so);;All Files (*.*)" );
    else if( nType == JS_FILE_TYPE_PFX )
        strType = QObject::tr("PFX Files (*.pfx *.p12 *.pem);;All Files(*.*)");

    QString selectedFilter;
    QString fileName = QFileDialog::getSaveFileName( parent,
                                                     QObject::tr("Save File"),
                                                     strCurPath,
                                                     strType,
                                                     &selectedFilter,
                                                     options );

    return fileName;
}

void getCKDate( const QDate date, CK_DATE *pCKDate )
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
            strVal += QString( "PathLengthConstraint=None" );
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
                strVal += QString( "%1:\n %2").arg( strType ).arg( pCurList->sNumVal.pValue );
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

    if( nType != DATA_STRING )
    {
        strMsg.remove( QRegExp("[\t\r\n\\s]") );
    }

    if( nType == DATA_HEX )
    {
        nLen = strMsg.length() / 2;

        if( strMsg.length() % 2 ) nLen++;

        return nLen;
    }
    else if( nType == DATA_BASE64 )
    {
        BIN bin = {0,0};
        JS_BIN_decodeBase64( strMsg.toStdString().c_str(), &bin );
        nLen = bin.nLen;
        JS_BIN_reset( &bin );
        return nLen;
    }

    return strData.length();
}

int getDataLen( const QString strType, const QString strData )
{
    int nType = DATA_STRING;

    QString strLower = strType.toLower();

    if( strLower == "hex" )
        nType = DATA_HEX;
    else if( strLower == "base64" )
        nType = DATA_BASE64;

    return getDataLen( nType, strData );
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
        srcString.remove( QRegExp("[\t\r\n\\s]") );
        JS_BIN_decodeHex( srcString.toStdString().c_str(), pBin );
    }
    else if( nType == DATA_BASE64 )
    {
        srcString.remove( QRegExp("[\t\r\n\\s]") );
        JS_BIN_decodeBase64( srcString.toStdString().c_str(), pBin );
    }
    else if( nType == DATA_URL )
    {
        char *pStr = NULL;
        JS_UTIL_decodeURL( srcString.toStdString().c_str(), &pStr );

        if( pStr )
        {
            JS_BIN_set( pBin, (unsigned char *)pStr, strlen(pStr));
            JS_free( pStr );
        }
    }
    else
    {
        JS_BIN_set( pBin, (unsigned char *)srcString.toStdString().c_str(), srcString.length() );
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
        JS_UTIL_encodeURL( pStr, &pOut );
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
    QString strFlag = QString( "%1" ).arg( uFlag );

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

    if( uState & CKS_RO_PUBLIC_SESSION ) strState += " | RO_PUBLIC_SESSION";
    if( uState & CKS_RO_USER_FUNCTIONS ) strState += " | RO_USER_FUNCTIONS";
    if( uState & CKS_RW_PUBLIC_SESSION ) strState += " | RW_PUBLIC_SESSION";
    if( uState & CKS_RW_SO_FUNCTIONS ) strState += " | RW_SO_FUNCTIONS";
    if( uState & CKS_RW_USER_FUNCTIONS ) strState += " | RW_USER_FUNCTIONS";

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
