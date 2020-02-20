#include "man_tree_item.h"

ManTreeItem::ManTreeItem()
{
    type_ = -1;
    slot_index_ = -1;

    setEditable(false);
}

ManTreeItem::ManTreeItem( const QString& text )
{
    type_ = -1;
    slot_index_ = -1;

    setText( text );
    setEditable(false);
}

void ManTreeItem::setType(int type)
{
    type_ = type;
}

void ManTreeItem::setSlotIndex(long slot_index)
{
    slot_index_ = slot_index;
}
