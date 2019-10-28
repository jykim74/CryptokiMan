#include <QStandardItem>

#include "man_tree_model.h"
#include "man_tree_item.h"
#include "js_pkcs11.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "slot_info.h"

ManTreeModel::ManTreeModel( QObject *parent )
    : QStandardItemModel(parent)
{
    initialize();
}

void ManTreeModel::initialize()
{
    clear();

    QStringList labels;
    labels << tr("SLot List");
    setHorizontalHeaderLabels( labels );

    ManTreeItem *item_ = new ManTreeItem();
    item_->setText( tr("No slot"));
    insertRow( 0, item_ );
}


void ManTreeModel::removeAllRightTable()
{
    if( right_table_ == NULL ) return;

    int row_cnt = right_table_->rowCount();

    for( int i =0; i < row_cnt; i++ )
        right_table_->removeRow(0);
}

void ManTreeModel::showGetInfo()
{
    int ret = 0;
    CK_INFO     sInfo;
    JSP11_CTX*  p11_ctx = NULL;

    memset( &sInfo, 0x00, sizeof(sInfo));

    p11_ctx = manApplet->mainWindow()->getP11CTX();

    ret = JS_PKCS11_GetInfo( p11_ctx, &sInfo );
    if( ret != CKR_OK ) return;

    removeAllRightTable();

    QString strMsg = "";

    int row = 0;
    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString( "cryptokiVersion")));
    strMsg = QString( "V%1.%2" ).arg( sInfo.cryptokiVersion.major ).arg( sInfo.cryptokiVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("flags")));
    strMsg = QString( "%1" ).arg( sInfo.flags );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("libraryDescription")));
    strMsg = QString( "%1" ).arg( (char *)sInfo.libraryDescription );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("libraryVersion")));
    strMsg = QString( "V%1.%2" ).arg( sInfo.libraryVersion.major).arg( sInfo.libraryVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("manufacturerID")));
    strMsg = QString( "%1" ).arg( (char *)sInfo.manufacturerID );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;
}

void ManTreeModel::showSlotInfo( int index )
{
    long uSlotID = -1;

    JSP11_CTX* p11_ctx = NULL;
    CK_SLOT_INFO stSlotInfo;

    QList<SlotInfo>& slotInfos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slotInfos.at(index);
    uSlotID = slotInfo.getSlotID();

    p11_ctx = manApplet->mainWindow()->getP11CTX();
    int rv = JS_PKCS11_GetSlotInfo( p11_ctx, uSlotID, &stSlotInfo );

    if( rv != CKR_OK )
    {
        return;
    }

    removeAllRightTable();

    int row = 0;
    QString strMsg = "";

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("Slot ID" )));
    strMsg = QString("%1").arg(uSlotID);
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("firmwareVersion" )));
    strMsg = QString( "V%1.%2").arg( stSlotInfo.firmwareVersion.major ).arg( stSlotInfo.firmwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ));
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("flags" )));
    strMsg = QString( "%1" ).arg( stSlotInfo.flags );
    if( stSlotInfo.flags & CKF_TOKEN_PRESENT )
        strMsg += " | token present";

    if( stSlotInfo.flags & CKF_REMOVABLE_DEVICE )
        strMsg += " | removable device";

    if( stSlotInfo.flags & CKF_HW_SLOT )
        strMsg += " | HW slot";


    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("hardwareVersion") ));
    strMsg = QString( "V%1.%2").arg( stSlotInfo.hardwareVersion.major ).arg( stSlotInfo.hardwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("manufacturerID")));
    strMsg = QString( "%1" ).arg( (char *)stSlotInfo.manufacturerID );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("slotDescription" )));
    strMsg = QString( "%1" ).arg( (char *)stSlotInfo.slotDescription );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;
}

void ManTreeModel::showTokenInfo(int index)
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);
    long uSlotID = slotInfo.getSlotID();

    int rv = JS_PKCS11_GetTokenInfo( p11_ctx, uSlotID, &sTokenInfo );
    if( rv != CKR_OK )
    {
        return;
    }

    removeAllRightTable();

    int row = 0;
    QString strMsg = "";

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("firmwareVersion" )));
    strMsg = QString( "V%1.%2").arg( sTokenInfo.firmwareVersion.major ).arg( sTokenInfo.firmwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("flags" )));
    strMsg = QString( "%1" ).arg( sTokenInfo.flags );

    if( sTokenInfo.flags & CKF_TOKEN_INITIALIZED ) strMsg += " | token initialized";
    if( sTokenInfo.flags & CKF_RNG ) strMsg += " | RNG";
    if( sTokenInfo.flags & CKF_WRITE_PROTECTED ) strMsg += " | write protected";
    if( sTokenInfo.flags & CKF_LOGIN_REQUIRED ) strMsg += " | login required";
    if( sTokenInfo.flags & CKF_USER_PIN_INITIALIZED ) strMsg += " | user pin initialized";
    if( sTokenInfo.flags & CKF_RESTORE_KEY_NOT_NEEDED ) strMsg += " | restore key not needed";
    if( sTokenInfo.flags & CKF_CLOCK_ON_TOKEN ) strMsg += " | clock on token";
    if( sTokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH ) strMsg += " | protected authentication path";
    if( sTokenInfo.flags & CKF_DUAL_CRYPTO_OPERATIONS ) strMsg += " | dual crypto operations";


    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("hardwareVersion" )));
    strMsg = QString( "V%1.%2").arg( sTokenInfo.hardwareVersion.major ).arg( sTokenInfo.hardwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("label") ));
    strMsg = QString("%1").arg( (char *)sTokenInfo.label );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("manufacturerID") ));
    strMsg = QString("%1").arg( (char *)sTokenInfo.manufacturerID );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("model") ));
    strMsg = QString("%1").arg( (char *)sTokenInfo.model );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("serialNumber") ));
    strMsg = QString("%1").arg( (char *)sTokenInfo.serialNumber );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulFreePrivateMemory") ));
    strMsg = QString("%1").arg( sTokenInfo.ulFreePrivateMemory );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulFreePublicMemory") ));
    strMsg = QString("%1").arg( sTokenInfo.ulFreePublicMemory );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMaxPinLen") ));
    strMsg = QString("%1").arg( sTokenInfo.ulMaxPinLen );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMaxRwSessionCount") ));
    strMsg = QString("%1").arg( sTokenInfo.ulMaxRwSessionCount );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMaxSessionCount") ));
    strMsg = QString("%1").arg( sTokenInfo.ulMaxSessionCount );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMinPinLen") ));
    strMsg = QString("%1").arg( sTokenInfo.ulMinPinLen );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulSessionCount") ));
    strMsg = QString("%1").arg( sTokenInfo.ulSessionCount );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulTotalPrivateMemory") ));
    strMsg = QString("%1").arg( sTokenInfo.ulTotalPrivateMemory );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulTotalPublicMemory") ));
    strMsg = QString("%1").arg( sTokenInfo.ulTotalPublicMemory );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;
}

void ManTreeModel::showMechanismInfo(int index)
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);
    long uSlotID = slotInfo.getSlotID();

    CK_MECHANISM_TYPE_PTR   pMechType = NULL;
    CK_ULONG ulMechCnt = 0;


    int rv = JS_PKCS11_GetMechanismList( p11_ctx, uSlotID, pMechType, &ulMechCnt );
    if( rv != CKR_OK )
    {
        return;
    }

    removeAllRightTable();

    pMechType = (CK_MECHANISM_TYPE_PTR)JS_calloc( ulMechCnt, sizeof(CK_MECHANISM_TYPE));
    rv = JS_PKCS11_GetMechanismList( p11_ctx, uSlotID, pMechType, &ulMechCnt );
    if( rv != CKR_OK )
    {
        return;
    }

    int row = 0;
    QString strMsg = "";

    for( int i = 0; i < ulMechCnt; i++ )
    {
        CK_MECHANISM_INFO   stMechInfo;

        rv = JS_PKCS11_GetMechanismInfo( p11_ctx, uSlotID, pMechType[i], &stMechInfo );
        if( rv != CKR_OK ) continue;

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("Type")));
        strMsg = JS_PKCS11_GetCKMName( pMechType[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("flags" )));
        strMsg = QString( "%1" ).arg( stMechInfo.flags );

        if( stMechInfo.flags & CKF_DECRYPT ) strMsg += " | Decrypt";
        if( stMechInfo.flags & CKF_DERIVE ) strMsg += " | Derive";
        if( stMechInfo.flags & CKF_DIGEST ) strMsg += " | Digest";
        if( stMechInfo.flags & CKF_ENCRYPT ) strMsg += " | Encrypt";
        if( stMechInfo.flags & CKF_GENERATE ) strMsg += " | Generate";
        if( stMechInfo.flags & CKF_GENERATE_KEY_PAIR ) strMsg += " | Generate key pair";
        if( stMechInfo.flags & CKF_HW ) strMsg += " | HW";
        if( stMechInfo.flags & CKF_SIGN ) strMsg += " | Sign";
        if( stMechInfo.flags & CKF_VERIFY ) strMsg += " | Verify";
        if( stMechInfo.flags & CKF_ENCRYPT ) strMsg += " | Encrypt";
        if( stMechInfo.flags & CKF_WRAP ) strMsg += " | Wrap";
        if( stMechInfo.flags & CKF_UNWRAP ) strMsg += " | Unwrap";
        if( stMechInfo.flags & CKF_SIGN_RECOVER ) strMsg += " | Sign recover";
        if( stMechInfo.flags & CKF_VERIFY_RECOVER ) strMsg += " | Verify recover";

        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString( "ulMaxKeySize" )));
        strMsg = QString("%1").arg( stMechInfo.ulMaxKeySize );
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString( "ulMinKeySize" )));
        strMsg = QString("%1").arg( stMechInfo.ulMinKeySize );
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("") ));
        right_table_->setItem( row, 1, new QTableWidgetItem( QString("") ));
        row++;
    }

    if( pMechType ) JS_free( pMechType );
}

void ManTreeModel::showSessionInfo(int index)
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);
    long uSlotID = slotInfo.getSlotID();

    CK_SESSION_INFO stSessInfo;

    removeAllRightTable();

    int rv = JS_PKCS11_GetSessionInfo( p11_ctx, slotInfo.getSessionHandle(), &stSessInfo );
    if( rv != CKR_OK )
    {
        return;
    }

    int row = 0;
    QString strMsg = "";

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("flags") ));
    strMsg = QString("%1").arg( stSessInfo.flags );

    if( stSessInfo.flags & CKF_RW_SESSION ) strMsg += " | CKF_RW_SESSION";
    if( stSessInfo.flags & CKF_SERIAL_SESSION ) strMsg += " | CKF_SERIAL_SESSION";

    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("slotID" )));
    strMsg = QString("%1").arg( stSessInfo.slotID );
    right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("state")));
    strMsg = QString("%1").arg( stSessInfo.state );

    if( stSessInfo.state & CKS_RO_PUBLIC_SESSION ) strMsg += " | RO_PUBLIC_SESSION";
    if( stSessInfo.state & CKS_RO_USER_FUNCTIONS ) strMsg += " | RO_USER_FUNCTIONS";
    if( stSessInfo.state & CKS_RW_PUBLIC_SESSION ) strMsg += " | RW_PUBLIC_SESSION";
    if( stSessInfo.state & CKS_RW_SO_FUNCTIONS ) strMsg += " | RW_SO_FUNCTIONS";
    if( stSessInfo.state & CKS_RW_USER_FUNCTIONS ) strMsg += " | RW_USER_FUNCTIONS";

    right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulDeviceError" )));
    strMsg = QString("%1 | " ).arg( stSessInfo.ulDeviceError );
    strMsg += JS_PKCS11_GetErrorMsg( stSessInfo.ulDeviceError );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

}

void ManTreeModel::showObjectsInfo(int index)
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);


    long uSession = slotInfo.getSessionHandle();
    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];

    removeAllRightTable();

    int ret = 0;

    ret = JS_PKCS11_FindObjectsInit( p11_ctx, uSession, NULL, 0 );
    ret = JS_PKCS11_FindObjects( p11_ctx, uSession, hObjects, 100, &uObjCnt );
    ret = JS_PKCS11_FindObjectsFinal( p11_ctx, uSession );


    int row = 0;
    QString strMsg = "";

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString( "Object Count" ) ) );
    strMsg = QString( "%1" ).arg( uObjCnt );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("") ));
    right_table_->setItem( row, 1, new QTableWidgetItem( QString("") ));
    row++;

    for( int i=0; i < uObjCnt; i++ )
    {
        CK_ULONG uSize = 0;
        QString strVal = "";

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("Handle" )));
        strVal = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem( QString( strVal) ));
        row++;


        JS_PKCS11_GetObjectSize( p11_ctx, uSession, hObjects[i], &uSize );
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("Size")));
        strVal = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem( QString(strVal) ));
        row++;

        CK_ATTRIBUTE_TYPE attrType = CKA_CLASS;
        BIN binVal = {0,0};
\

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("Class")));
        JS_PKCS11_GetAtrributeValue2( p11_ctx, uSession, hObjects[i], attrType, &binVal );
        strVal = JS_PKCS11_GetCKOName( JS_BIN_long( &binVal ) );
        JS_BIN_reset( &binVal );
        right_table_->setItem( row, 1, new QTableWidgetItem( strVal ));
        row++;

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
        right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
        row++;
    }
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

void ManTreeModel::showCertificateInfo( int index, long hObject )
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);

    long hSession = slotInfo.getSessionHandle();

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;

    removeAllRightTable();

    if( hObject < 0 )
    {
        CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
        CK_ATTRIBUTE sTemplate[1] = {
            { CKA_CLASS, &objClass, sizeof(objClass) }
        };

        rv = JS_PKCS11_FindObjectsInit( p11_ctx, hSession, sTemplate, 1 );
        rv = JS_PKCS11_FindObjects( p11_ctx, hSession, hObjects, 100, &uObjCnt );
        rv = JS_PKCS11_FindObjectsFinal( p11_ctx, hSession );
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    int row = 0;
    QString strMsg = "";

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("Certificate count" ) ) );
    strMsg = QString("%1").arg( uObjCnt );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
    right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
    row++;

    for( int i=0; i < uObjCnt; i++ )
    {
        char    *pStr = NULL;
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
        row++;

        CK_ATTRIBUTE_TYPE attrType = CKA_LABEL;
        BIN binVal = {0,0};

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_string( &binVal, &pStr );
        strMsg = pStr;
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("label")));
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );

        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }
        row++;

        attrType = CKA_ID;

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_string( &binVal, &pStr );
        strMsg = pStr;
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("label")));
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }
        row++;

        attrType = CKA_VALUE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_string( &binVal, &pStr );
        strMsg = pStr;
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("label")));
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }
        row++;

        attrType = CKA_MODIFIABLE;

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool( &binVal );
        JS_BIN_reset( &binVal );
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("label")));
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );

        row++;

        attrType = CKA_TRUSTED;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool( &binVal );
        JS_BIN_reset( &binVal );
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("label")));
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        attrType = CKA_PRIVATE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool( &binVal );
        JS_BIN_reset( &binVal );
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("label")));
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
        right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
        row++;
    }
}

void ManTreeModel::showPublicKeyInfo( int index, long hObject )
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);

    long hSession = slotInfo.getSessionHandle();
    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;

    removeAllRightTable();

    if( hObject < 0 )
    {
        CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
        CK_ATTRIBUTE sTemplate[1] = {
            { CKA_CLASS, &objClass, sizeof(objClass) }
        };

        rv = JS_PKCS11_FindObjectsInit( p11_ctx, hSession, sTemplate, 1 );
        rv = JS_PKCS11_FindObjects( p11_ctx, hSession, hObjects, 100, &uObjCnt );
        rv = JS_PKCS11_FindObjectsFinal( p11_ctx, hSession );
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    int row = 0;
    QString strMsg = "";

    strMsg = QString("%1").arg( uObjCnt );
    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("PublicKey Count")));
    right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
    right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
    row++;

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pStr = NULL;
        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
        row++;

        CK_ATTRIBUTE_TYPE attrType = CKA_LABEL;
        BIN binVal = {0,0};

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_string( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("label")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
        row++;

        attrType = CKA_KEY_TYPE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = JS_PKCS11_GetCKKName( JS_BIN_long(&binVal));
        JS_BIN_reset(&binVal);
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_KEY_TYPE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_ID;

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_ID")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_MODULUS;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_MODULUS")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_PUBLIC_EXPONENT;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_PUBLIC_EXPONENT")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_EC_PARAMS;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_EC_PARAMS")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_EC_POINT;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_EC_POINT")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_TOKEN;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool( &binVal );
        JS_BIN_reset( &binVal );

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_TOKEN")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_WRAP;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool( &binVal );
        JS_BIN_reset( &binVal );

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_WRAP")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_ENCRYPT;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool( &binVal );
        JS_BIN_reset( &binVal );

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_ENCRYPT")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_VERIFY;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool( &binVal );
        JS_BIN_reset( &binVal );

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_VERIFY")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_PRIVATE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool( &binVal );
        JS_BIN_reset( &binVal );

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_PRIVATE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_MODIFIABLE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool( &binVal );
        JS_BIN_reset( &binVal );

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_MODIFIABLE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_DERIVE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool( &binVal );
        JS_BIN_reset( &binVal );

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_DERIVE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
        right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
        row++;

    }
}

void ManTreeModel::showPrivateKeyInfo( int index, long hObject )
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);

    long hSession = slotInfo.getSessionHandle();

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;

    removeAllRightTable();

    if( hObject < 0 )
    {
        CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE sTemplate[1] = {
            { CKA_CLASS, &objClass, sizeof(objClass) }
        };

        rv = JS_PKCS11_FindObjectsInit( p11_ctx, hSession, sTemplate, 1 );
        rv = JS_PKCS11_FindObjects( p11_ctx, hSession, hObjects, 100, &uObjCnt );
        rv = JS_PKCS11_FindObjectsFinal( p11_ctx, hSession );
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    int row = 0;
    QString strMsg = "";

    strMsg = QString("%1").arg( uObjCnt );

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("PrivateKey Count")));
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ));
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
    right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
    row++;

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pStr = NULL;
        strMsg = QString("%1").arg( hObjects[i] );

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
        row++;

        CK_ATTRIBUTE_TYPE attrType = CKA_LABEL;
        BIN binVal = {0,0};

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("label")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_KEY_TYPE;

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = JS_PKCS11_GetCKKName( JS_BIN_long( &binVal ) );
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_KEY_TYPE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_ID;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_ID")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_SUBJECT;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_SUBJECT")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_MODULUS;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_MODULUS")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_PUBLIC_EXPONENT;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_PUBLIC_EXPONENT")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_PRIVATE_EXPONENT;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_PRIVATE_EXPONENT")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_PRIME_1;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_PRIME_1")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_PRIME_2;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_PRIME_2")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_EXPONENT_1;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_EXPONENT_1")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_EXPONENT_2;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_EXPONENT_2")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_EC_PARAMS;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_EC_PARAMS")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_VALUE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_VALUE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_TOKEN;

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_TOKEN")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_SENSITIVE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_SENSITIVE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_UNWRAP;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_UNWRAP")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_SIGN;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_SIGN")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_DECRYPT;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_DECRYPT")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_MODIFIABLE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_MODIFIABLE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_DERIVE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_DERIVE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
        right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
        row++;
    }
}

void ManTreeModel::showSecretKeyInfo( int index, long hObject )
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);

    long hSession = slotInfo.getSessionHandle();

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;

    removeAllRightTable();

    if( hObject < 0 )
    {
        CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
        CK_ATTRIBUTE sTemplate[1] = {
            { CKA_CLASS, &objClass, sizeof(objClass) }
        };

        rv = JS_PKCS11_FindObjectsInit( p11_ctx, hSession, sTemplate, 1 );
        rv = JS_PKCS11_FindObjects( p11_ctx, hSession, hObjects, 100, &uObjCnt );
        rv = JS_PKCS11_FindObjectsFinal( p11_ctx, hSession );
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    int row = 0;
    QString strMsg = "";

    strMsg = QString("%1").arg( uObjCnt );
    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("SecretKey Count")));
    right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
    right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
    row++;

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pStr = NULL;
        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        CK_ATTRIBUTE_TYPE attrType = CKA_LABEL;
        BIN binVal = {0,0};

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_string( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("label")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_KEY_TYPE;

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = JS_PKCS11_GetCKKName( JS_BIN_long(&binVal) );
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_KEY_TYPE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_ID;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_ID")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_VALUE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_VALUE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_VALUE_LEN;

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = QString("%1").arg( JS_BIN_long(&binVal));
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_VALUE_LEN")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_TOKEN;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_TOKEN")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_PRIVATE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_PRIVATE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_SENSITIVE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_SENSITIVE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_ENCRYPT;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_ENCRYPT")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_DECRYPT;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_DECRYPT")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_SIGN;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_SIGN")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_VERIFY;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_VERIFY")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_WRAP;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_WRAP")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_UNWRAP;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_UNWRAP")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_MODIFIABLE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_MODIFIABLE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;


        attrType = CKA_DERIVE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_DERIVE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
        right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
        row++;
    }
}

void ManTreeModel::showDataInfo( int index, long hObject )
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);

    long hSession = slotInfo.getSessionHandle();

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;

    removeAllRightTable();

    if( hObject < 0 )
    {
        CK_OBJECT_CLASS objClass = CKO_DATA;
        CK_ATTRIBUTE sTemplate[1] = {
            { CKA_CLASS, &objClass, sizeof(objClass) }
        };

        rv = JS_PKCS11_FindObjectsInit( p11_ctx, hSession, sTemplate, 1 );
        rv = JS_PKCS11_FindObjects( p11_ctx, hSession, hObjects, 100, &uObjCnt );
        rv = JS_PKCS11_FindObjectsFinal( p11_ctx, hSession );
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    int row = 0;
    QString strMsg = "";

    strMsg = QString("%1").arg( uObjCnt );
    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("Data Count")));
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
    right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
    row++;

    for( int i=0; i < uObjCnt; i++ )
    {
        char *pStr = NULL;
        strMsg = QString("%1").arg( hObjects[0] );
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        CK_ATTRIBUTE_TYPE attrType = CKA_LABEL;
        BIN binVal = {0,0};

        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_string( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_LABEL")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_VALUE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
        JS_BIN_reset(&binVal);
        if( pStr )
        {
            JS_free(pStr);
            pStr = NULL;
        }

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_VALUE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_TOKEN;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_TOKEN")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_PRIVATE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_PRIVATE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        attrType = CKA_MODIFIABLE;
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hSession, hObjects[i], attrType, &binVal );
        strMsg = getBool(&binVal);
        JS_BIN_reset(&binVal);

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("CKA_MODIFIABLE")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));
        row++;

        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
        right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
        row++;
    }
}

void ManTreeModel::setRightTable(QTableWidget *right_table)
{
    right_table_ = right_table;
}
