#include <QStandardItem>

#include "man_tree_model.h"
#include "man_tree_item.h"
#include "js_pkcs11.h"
#include "man_applet.h"
#include "mainwindow.h"

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

void ManTreeModel::showSlotInfo()
{
    long uSlotID = -1;

    JSP11_CTX* p11_ctx = NULL;
    CK_SLOT_INFO stSlotInfo;

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


void ManTreeModel::setRightTable(QTableWidget *right_table)
{
    right_table_ = right_table;
}
