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

void ManTreeModel::setRightTable(QTableWidget *right_table)
{
    right_table_ = right_table;
}
