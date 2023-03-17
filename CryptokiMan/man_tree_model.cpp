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

    ManTreeItem *item = new ManTreeItem();

    item->setText( "No slot" );
    item->setIcon( QIcon( ":/images/cryptokiman.png") );

    insertRow( 0, item );
}
