#include <QStandardItem>

#include "man_tree_model.h"
#include "man_tree_item.h"
#include "js_pkcs11.h"

ManTreeModel::ManTreeModel( QObject *parent )
    : QStandardItemModel(parent)
{
    initialize();
    p11_ctx_ = NULL;
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

void ManTreeModel::setP11CTX(JSP11_CTX *pCTX)
{
    p11_ctx_ = pCTX;
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

    memset( &sInfo, 0x00, sizeof(sInfo));

    ret = JS_PKCS11_GetInfo( p11_ctx_, &sInfo );
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

void ManTreeModel::setRightTable(QTableWidget *right_table)
{
    right_table_ = right_table;
}
