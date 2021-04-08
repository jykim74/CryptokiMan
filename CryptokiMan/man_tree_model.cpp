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
    JP11_CTX*  p11_ctx = NULL;

    memset( &sInfo, 0x00, sizeof(sInfo));

    p11_ctx = manApplet->getP11CTX();

    ret = JS_PKCS11_GetInfo( p11_ctx, &sInfo );
    if( ret != CKR_OK ) return;

    removeAllRightTable();

    QString strMsg = "";
    QStringList strList;

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
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0) ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("libraryVersion")));
    strMsg = QString( "V%1.%2" ).arg( sInfo.libraryVersion.major).arg( sInfo.libraryVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("manufacturerID")));
    strMsg = QString( "%1" ).arg( (char *)sInfo.manufacturerID );
    strList = strMsg.split( "  " );
    if( strList.size() >0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0) ) );
    row++;
}

void ManTreeModel::showSlotInfo( int index )
{
    long uSlotID = -1;

    JP11_CTX* p11_ctx = NULL;
    CK_SLOT_INFO stSlotInfo;

    QList<SlotInfo>& slotInfos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slotInfos.at(index);
    uSlotID = slotInfo.getSlotID();

    p11_ctx = manApplet->getP11CTX();
    int rv = JS_PKCS11_GetSlotInfo( p11_ctx, uSlotID, &stSlotInfo );

    if( rv != CKR_OK )
    {
        return;
    }

    removeAllRightTable();

    int row = 0;
    QString strMsg = "";
    QStringList strList;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("Slot ID" )));
    strMsg = QString("%1").arg(uSlotID);
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("firmwareVersion" )));
    strMsg = QString( "V%1.%2").arg( stSlotInfo.firmwareVersion.major ).arg( stSlotInfo.firmwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ));
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
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
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("hardwareVersion") ));
    strMsg = QString( "V%1.%2").arg( stSlotInfo.hardwareVersion.major ).arg( stSlotInfo.hardwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("manufacturerID")));
    strMsg = QString( "%1" ).arg( (char *)stSlotInfo.manufacturerID );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0) ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("slotDescription" )));
    strMsg = QString( "%1" ).arg( (char *)stSlotInfo.slotDescription );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0) ) );
    row++;
}

void ManTreeModel::showTokenInfo(int index)
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
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
    QStringList strList;

    right_table_->insertRow( row );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("firmwareVersion" )));
    strMsg = QString( "V%1.%2").arg( sTokenInfo.firmwareVersion.major ).arg( sTokenInfo.firmwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
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
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("hardwareVersion" )));
    strMsg = QString( "V%1.%2").arg( sTokenInfo.hardwareVersion.major ).arg( sTokenInfo.hardwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("label") ));
    strMsg = QString("%1").arg( (char *)sTokenInfo.label );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0)) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("manufacturerID") ));
    strMsg = QString("%1").arg( (char *)sTokenInfo.manufacturerID );    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0)) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("model") ));
    strMsg = QString("%1").arg( (char *)sTokenInfo.model );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0)) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("serialNumber") ));
    strMsg = QString("%1").arg( (char *)sTokenInfo.serialNumber );
//    strList = strMsg.split( "  " );
    strMsg.truncate(16);
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulFreePrivateMemory") ));
    strMsg = QString("%1").arg( sTokenInfo.ulFreePrivateMemory );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulFreePublicMemory") ));
    strMsg = QString("%1").arg( sTokenInfo.ulFreePublicMemory );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMaxPinLen") ));
    strMsg = QString("%1").arg( sTokenInfo.ulMaxPinLen );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMaxRwSessionCount") ));
    strMsg = QString("%1").arg( sTokenInfo.ulMaxRwSessionCount );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMaxSessionCount") ));
    strMsg = QString("%1").arg( sTokenInfo.ulMaxSessionCount );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMinPinLen") ));
    strMsg = QString("%1").arg( sTokenInfo.ulMinPinLen );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulSessionCount") ));
    strMsg = QString("%1").arg( sTokenInfo.ulSessionCount );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulTotalPrivateMemory") ));
    strMsg = QString("%1").arg( sTokenInfo.ulTotalPrivateMemory );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulTotalPublicMemory") ));
    strMsg = QString("%1").arg( sTokenInfo.ulTotalPublicMemory );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;
}

void ManTreeModel::showMechanismInfo(int index)
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
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
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("Type")));
        strMsg = JS_PKCS11_GetCKMName( pMechType[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
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
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString( "ulMaxKeySize" )));
        strMsg = QString("%1").arg( stMechInfo.ulMaxKeySize );
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString( "ulMinKeySize" )));
        strMsg = QString("%1").arg( stMechInfo.ulMinKeySize );
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("") ));
        right_table_->setItem( row, 1, new QTableWidgetItem( QString("") ));
        row++;
    }

    if( pMechType ) JS_free( pMechType );
}

void ManTreeModel::showSessionInfo(int index)
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);
    long uSlotID = slotInfo.getSlotID();

    CK_SESSION_INFO stSessInfo;
    p11_ctx->hSession = slotInfo.getSessionHandle();

    removeAllRightTable();

    int rv = JS_PKCS11_GetSessionInfo( p11_ctx, &stSessInfo );
    if( rv != CKR_OK )
    {
        return;
    }

    int row = 0;
    QString strMsg = "";

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("flags") ));
    strMsg = QString("%1").arg( stSessInfo.flags );

    if( stSessInfo.flags & CKF_RW_SESSION ) strMsg += " | CKF_RW_SESSION";
    if( stSessInfo.flags & CKF_SERIAL_SESSION ) strMsg += " | CKF_SERIAL_SESSION";

    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("slotID" )));
    strMsg = QString("%1").arg( stSessInfo.slotID );
    right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
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
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulDeviceError" )));
    strMsg = QString("%1 | " ).arg( stSessInfo.ulDeviceError );
    strMsg += JS_PKCS11_GetErrorMsg( stSessInfo.ulDeviceError );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

}

void ManTreeModel::showObjectsInfo(int index)
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);


    p11_ctx->hSession = slotInfo.getSessionHandle();
    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];

    removeAllRightTable();

    int ret = 0;

    ret = JS_PKCS11_FindObjectsInit( p11_ctx, NULL, 0 );
    ret = JS_PKCS11_FindObjects( p11_ctx, hObjects, 100, &uObjCnt );
    ret = JS_PKCS11_FindObjectsFinal( p11_ctx );


    int row = 0;
    QString strMsg = "";

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString( "Object Count" ) ) );
    strMsg = QString( "%1" ).arg( uObjCnt );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("") ));
    right_table_->setItem( row, 1, new QTableWidgetItem( QString("") ));
    row++;

    for( int i=0; i < uObjCnt; i++ )
    {
        CK_ULONG uSize = 0;
        QString strVal = "";

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("Handle" )));
        strVal = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem( QString( strVal) ));
        row++;


        JS_PKCS11_GetObjectSize( p11_ctx, hObjects[i], &uSize );
        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("Size")));
        strVal = QString("%1").arg( uSize );
        right_table_->setItem( row, 1, new QTableWidgetItem( QString(strVal) ));
        row++;

        CK_ATTRIBUTE_TYPE attrType = CKA_CLASS;
        BIN binVal = {0,0};
\

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("Class")));
        JS_PKCS11_GetAtrributeValue2( p11_ctx, hObjects[i], attrType, &binVal );
        long uVal = 0;
        memcpy( &uVal, binVal.pVal, binVal.nLen );
        strVal = JS_PKCS11_GetCKOName( uVal );
        JS_BIN_reset( &binVal );
        right_table_->setItem( row, 1, new QTableWidgetItem( strVal ));
        row++;

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
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

void ManTreeModel::showAttribute( int nSlotIdx, int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj )
{
    int ret = 0;

    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at( nSlotIdx );

    p11_ctx->hSession = slotInfo.getSessionHandle();

    char    *pStr = NULL;
    QString strMsg;
    BIN     binVal = {0,0};
    int nRow = right_table_->rowCount();

    ret = JS_PKCS11_GetAtrributeValue2( p11_ctx, hObj, uAttribute, &binVal );
    if( ret != CKR_OK ) return;

    if( nValType == ATTR_VAL_BOOL )
    {
        strMsg = getBool( &binVal );
    }
    else if( nValType == ATTR_VAL_STRING )
    {
        JS_BIN_string( &binVal, &pStr );
        strMsg = pStr;
    }
    else if( nValType == ATTR_VAL_HEX )
    {
        JS_BIN_encodeHex( &binVal, &pStr );
        strMsg = pStr;
    }
    else if( nValType == ATTR_VAL_KEY_NAME )
    {
        long uVal = 0;
        memcpy( &uVal, binVal.pVal, binVal.nLen );
        strMsg = JS_PKCS11_GetCKKName( uVal );
    }
    else if( nValType == ATTR_VAL_LEN )
    {
        strMsg = QString("%1").arg( JS_BIN_long(&binVal));
    }
    else if( nValType == ATTR_VAL_DATE )
    {

        if( binVal.nLen >= 8 )
        {
            char    sYear[5];
            char    sMonth[3];
            char    sDay[3];
            CK_DATE *pDate = (CK_DATE *)binVal.pVal;

            memset( sYear, 0x00, sizeof(sYear));
            memset( sMonth, 0x00, sizeof(sMonth));
            memset( sDay, 0x00, sizeof(sDay));

            memcpy( sYear, pDate->year, 4 );
            memcpy( sMonth, pDate->month, 2 );
            memcpy( sDay, pDate->day, 2 );

            strMsg = QString( "%1-%2-%3").arg( sYear ).arg( sMonth ).arg(sDay);
        }
        else
        {
            JS_BIN_encodeHex( &binVal, &pStr );
            strMsg = pStr;
        }

    }

    QString strName = JS_PKCS11_GetCKAName( uAttribute );

    right_table_->insertRow( nRow );
    right_table_->setItem( nRow, 0, new QTableWidgetItem( strName ) );
    right_table_->setItem( nRow, 1, new QTableWidgetItem( strMsg ) );

    JS_BIN_reset( &binVal );
    if( pStr ) JS_free( pStr );
}

void ManTreeModel::showCertificateInfo( int index, long hObject )
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);

    p11_ctx->hSession = slotInfo.getSessionHandle();

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

        rv = JS_PKCS11_FindObjectsInit( p11_ctx, sTemplate, 1 );
        rv = JS_PKCS11_FindObjects( p11_ctx, hObjects, 100, &uObjCnt );
        rv = JS_PKCS11_FindObjectsFinal( p11_ctx );
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    QString strMsg = "";

    right_table_->insertRow( 0 );
    right_table_->setRowHeight( 0, 10 );
    right_table_->setItem( 0, 0, new QTableWidgetItem( QString("Certificate count" ) ) );
    strMsg = QString("%1").arg( uObjCnt );
    right_table_->setItem( 0, 1, new QTableWidgetItem( strMsg ) );

    right_table_->insertRow( 1 );
    right_table_->setRowHeight( 1, 10 );
    right_table_->setItem( 1, 0, new QTableWidgetItem(QString("")));
    right_table_->setItem( 1, 1, new QTableWidgetItem(QString("")));

    for( int i=0; i < uObjCnt; i++ )
    {
        int     row = right_table_->rowCount();

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        showAttribute( index, ATTR_VAL_STRING, CKA_LABEL, hObjects[i] );
        showAttribute( index, ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        showAttribute( index, ATTR_VAL_STRING, CKA_SUBJECT, hObjects[i] );
        showAttribute( index, ATTR_VAL_HEX, CKA_VALUE, hObjects[i] );
        showAttribute( index, ATTR_VAL_BOOL, CKA_MODIFIABLE, hObjects[i] );
        showAttribute( index, ATTR_VAL_BOOL, CKA_TRUSTED, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_PRIVATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_START_DATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_END_DATE, hObjects[i] );

        row = right_table_->rowCount();
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
        right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
    }
}

void ManTreeModel::showPublicKeyInfo( int index, long hObject )
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);

    p11_ctx->hSession = slotInfo.getSessionHandle();
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

        rv = JS_PKCS11_FindObjectsInit( p11_ctx, sTemplate, 1 );
        rv = JS_PKCS11_FindObjects( p11_ctx, hObjects, 100, &uObjCnt );
        rv = JS_PKCS11_FindObjectsFinal( p11_ctx );
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    QString strMsg = "";

    strMsg = QString("%1").arg( uObjCnt );
    right_table_->insertRow( 0 );
    right_table_->setRowHeight( 0, 10 );
    right_table_->setItem( 0, 0, new QTableWidgetItem(QString("PublicKey Count")));
    right_table_->setItem( 0, 1, new QTableWidgetItem(strMsg));

    right_table_->insertRow( 1 );
    right_table_->setRowHeight( 1, 10 );
    right_table_->setItem( 1, 0, new QTableWidgetItem(QString("")));
    right_table_->setItem( 1, 1, new QTableWidgetItem(QString("")));


    for( int i=0; i < uObjCnt; i++ )
    {
        int row = right_table_->rowCount();

        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        showAttribute( index, ATTR_VAL_STRING, CKA_LABEL, hObjects[i]);
        showAttribute( index, ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, hObjects[i] );
        showAttribute( index, ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        showAttribute( index, ATTR_VAL_HEX, CKA_MODULUS, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_PUBLIC_EXPONENT, hObjects[i] );
        showAttribute( index, ATTR_VAL_HEX, CKA_EC_PARAMS, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_EC_POINT, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_TOKEN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_WRAP, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_ENCRYPT, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_VERIFY, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_PRIVATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_MODIFIABLE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_DERIVE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_START_DATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_END_DATE, hObjects[i] );

        row = right_table_->rowCount();
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
        right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
    }
}

void ManTreeModel::showPrivateKeyInfo( int index, long hObject )
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);

    p11_ctx->hSession = slotInfo.getSessionHandle();

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

        rv = JS_PKCS11_FindObjectsInit( p11_ctx, sTemplate, 1 );
        rv = JS_PKCS11_FindObjects( p11_ctx, hObjects, 100, &uObjCnt );
        rv = JS_PKCS11_FindObjectsFinal( p11_ctx );
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    QString strMsg = "";

    strMsg = QString("%1").arg( uObjCnt );

    right_table_->insertRow( 0 );
    right_table_->setRowHeight( 0, 10 );
    right_table_->setItem( 0, 0, new QTableWidgetItem(QString("PrivateKey Count")));
    right_table_->setItem( 0, 1, new QTableWidgetItem( strMsg ));


    right_table_->insertRow( 1 );
    right_table_->setRowHeight( 1, 10 );
    right_table_->setItem( 1, 0, new QTableWidgetItem(QString("")));
    right_table_->setItem( 1, 1, new QTableWidgetItem(QString("")));


    for( int i=0; i < uObjCnt; i++ )
    {
        int row = right_table_->rowCount();
        strMsg = QString("%1").arg( hObjects[i] );

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        showAttribute( index, ATTR_VAL_STRING, CKA_LABEL, hObjects[i]);
        showAttribute( index, ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, hObjects[i] );
        showAttribute( index, ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        showAttribute( index, ATTR_VAL_HEX, CKA_SUBJECT, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_MODULUS, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_PUBLIC_EXPONENT, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_PRIVATE_EXPONENT, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_PRIME_1, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_PRIME_2, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_EXPONENT_1, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_EXPONENT_2, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_EC_PARAMS, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_VALUE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_TOKEN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_SENSITIVE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_UNWRAP, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_SIGN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_DECRYPT, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_MODIFIABLE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_DERIVE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_EXTRACTABLE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_START_DATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_END_DATE, hObjects[i] );


        row = right_table_->rowCount();
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
        right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
    }
}

void ManTreeModel::showSecretKeyInfo( int index, long hObject )
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);

    p11_ctx->hSession = slotInfo.getSessionHandle();

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

        rv = JS_PKCS11_FindObjectsInit( p11_ctx, sTemplate, 1 );
        rv = JS_PKCS11_FindObjects( p11_ctx, hObjects, 100, &uObjCnt );
        rv = JS_PKCS11_FindObjectsFinal( p11_ctx );
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    QString strMsg = "";

    strMsg = QString("%1").arg( uObjCnt );
    right_table_->insertRow( 0 );
    right_table_->setRowHeight( 0, 10 );
    right_table_->setItem( 0, 0, new QTableWidgetItem(QString("SecretKey Count")));
    right_table_->setItem( 0, 1, new QTableWidgetItem(strMsg) );

    right_table_->insertRow( 1 );
    right_table_->setRowHeight( 1, 10 );
    right_table_->setItem( 1, 0, new QTableWidgetItem(QString("")));
    right_table_->setItem( 1, 1, new QTableWidgetItem(QString("")));

    for( int i=0; i < uObjCnt; i++ )
    {
        int row = right_table_->rowCount();
        strMsg = QString("%1").arg( hObjects[i] );

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));

        showAttribute( index, ATTR_VAL_STRING, CKA_LABEL, hObjects[i]);
        showAttribute( index, ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_ID, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_VALUE, hObjects[i]);
        showAttribute( index, ATTR_VAL_LEN, CKA_VALUE_LEN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_TOKEN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_PRIVATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_SENSITIVE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_ENCRYPT, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_DECRYPT, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_SIGN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_VERIFY, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_WRAP, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_UNWRAP, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_MODIFIABLE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_DERIVE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_EXTRACTABLE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_START_DATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_END_DATE, hObjects[i] );

        row = right_table_->rowCount();
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
        right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
    }
}

void ManTreeModel::showDataInfo( int index, long hObject )
{
    JP11_CTX* p11_ctx = manApplet->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);

    p11_ctx->hSession = slotInfo.getSessionHandle();

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

        rv = JS_PKCS11_FindObjectsInit( p11_ctx, sTemplate, 1 );
        rv = JS_PKCS11_FindObjects( p11_ctx, hObjects, 100, &uObjCnt );
        rv = JS_PKCS11_FindObjectsFinal( p11_ctx);
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    QString strMsg = "";

    strMsg = QString("%1").arg( uObjCnt );
    right_table_->insertRow( 0 );
    right_table_->setRowHeight( 0, 10 );
    right_table_->setItem( 0, 0, new QTableWidgetItem(QString("Data Count")));
    right_table_->setItem( 0, 1, new QTableWidgetItem( strMsg ) );

    right_table_->insertRow( 1 );
    right_table_->setRowHeight( 1, 10 );
    right_table_->setItem( 1, 0, new QTableWidgetItem(QString("")));
    right_table_->setItem( 1, 1, new QTableWidgetItem(QString("")));


    for( int i=0; i < uObjCnt; i++ )
    {
        int row = right_table_->rowCount();
        strMsg = QString("%1").arg( hObjects[0] );
        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));


        showAttribute( index, ATTR_VAL_STRING, CKA_LABEL, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_VALUE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_TOKEN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_PRIVATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_MODIFIABLE, hObjects[i]);

        row = right_table_->rowCount();
        right_table_->insertRow( row );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("")));
        right_table_->setItem( row, 1, new QTableWidgetItem(QString("")));
    }
}

void ManTreeModel::setRightTable(QTableWidget *right_table)
{
    right_table_ = right_table;
}
