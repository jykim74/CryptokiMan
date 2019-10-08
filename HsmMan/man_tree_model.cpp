#include "man_tree_model.h"
#include "man_tree_item.h"

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

    ManTreeItem *pItem = new ManTreeItem();
    pItem->setText( tr("No slot"));
    insertRow( 0, pItem );
}
