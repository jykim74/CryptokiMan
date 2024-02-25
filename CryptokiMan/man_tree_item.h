/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAN_TREE_ITEM_H
#define MAN_TREE_ITEM_H

#include "common.h"
#include <QStandardItem>

#define     HM_TREE_ROOT            "ROOT"
#define     HM_TREE_SLOT            "SLOT"
#define     HM_TREE_TOKEN           "TOKEN"
#define     HM_TREE_MECHANISM       "MECHANISM"
#define     HM_TREE_SESSION         "SESSION"
#define     HM_TREE_OBJECTS         "OBJECTS"
#define     HM_TREE_CERTIFICATE     "CERTIFICATE"
#define     HM_TREE_PUBLICKEY       "PUBLICKEY"
#define     HM_TREE_PRIVATEKEY      "PRIVATEKEY"
#define     HM_TREE_SECRETKEY       "SECRETKEY"
#define     HM_TREE_DATA            "DATA"




class ManTreeItem : public QStandardItem
{
public:
    ManTreeItem();
    ManTreeItem( const QString& text );


    int getType() { return type_; };
    long getSlotIndex() { return slot_index_; };

    void setType( int type );
    void setSlotIndex( long slot_index );


private:
    int     type_;
    long    slot_index_;
};

#endif // MAN_TREE_ITEM_H
