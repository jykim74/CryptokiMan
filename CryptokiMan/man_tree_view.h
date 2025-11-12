/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAN_TREE_VIEW_H
#define MAN_TREE_VIEW_H

#include <QTreeView>
#include <QModelIndex>
#include "man_tree_item.h"

class ManTreeItem;

class ManTreeView : public QTreeView
{
    Q_OBJECT
public:
    ManTreeView( QWidget* parent = nullptr );
    int currentSlotIndex();
    ManTreeItem* getItem( int nSlotIndex, int nType );

private slots:
    void onItemClicked( const QModelIndex& index );
    void showContextMenu( QPoint point );

public slots:
    void showTypeList( int nSlotIndex, int nType );

private:
    ManTreeItem* currentItem();
};

#endif // MAN_TREE_VIEW_H
