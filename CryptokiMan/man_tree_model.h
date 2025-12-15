/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAN_TREE_MODEL_H
#define MAN_TREE_MODEL_H

#include "js_pkcs11.h"

#include <QStandardItemModel>
#include <QTableWidget>


class ManTreeItem;
class ManTreeView;

class ManTreeModel : public QStandardItemModel
{
public:
    ManTreeModel( QObject *parent = nullptr );
    ~ManTreeModel();
    void clickTreeMenu( int nSlotIndex, int nType );

    void Reset();

    void makeTree();
    void clearTree();

    ManTreeView* getTreeView() { return tree_view_; };
    void openSlot( int index );
    void closeSlot( int index );
    void loginSlot( int index );
    void logoutSlot( int index );
    void closeAllSlot();

    ManTreeItem* currentTreeItem();
    ManTreeItem* getRootItem();

private:
    void initialize();

    ManTreeView* tree_view_;
};

#endif // MAN_TREE_MODEL_H
