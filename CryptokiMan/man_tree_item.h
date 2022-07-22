#ifndef MAN_TREE_ITEM_H
#define MAN_TREE_ITEM_H

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

#define     HM_ITEM_TYPE_ROOT               0
#define     HM_ITEM_TYPE_SLOT               1
#define     HM_ITEM_TYPE_TOKEN              2
#define     HM_ITEM_TYPE_MECHANISM          3
#define     HM_ITEM_TYPE_SESSION            4
#define     HM_ITEM_TYPE_OBJECTS            5
#define     HM_ITEM_TYPE_CERTIFICATE        6
#define     HM_ITEM_TYPE_PUBLICKEY          7
#define     HM_ITEM_TYPE_PRIVATEKEY         8
#define     HM_ITEM_TYPE_SECRETKEY          9
#define     HM_ITEM_TYPE_DATA               10
#define     HM_ITEM_TYPE_CERTIFICATE_OBJECT 11
#define     HM_ITEM_TYPE_PUBLICKEY_OBJECT   12
#define     HM_ITEM_TYPE_PRIVATEKEY_OBJECT  13
#define     HM_ITEM_TYPE_SECRETKEY_OBJECT   14
#define     HM_ITEM_TYPE_DATA_OBJECT        15


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
