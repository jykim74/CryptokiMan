#include "man_tree_item.h"

ManTreeItem::ManTreeItem()
{
    type_ = -1;
    status_ = -1;
}

ManTreeItem::ManTreeItem( const QString& text )
{
    type_ = -1;
    status_ = -1;
    setText( text );
}

void ManTreeItem::setType(int type)
{
    type_ = type;
}

void ManTreeItem::setStatus(int status)
{
    status_ = status;
}
