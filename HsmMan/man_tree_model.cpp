#include "man_tree_model.h"
#include "man_tree_item.h"

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
