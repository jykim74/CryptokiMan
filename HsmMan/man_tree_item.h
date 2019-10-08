#ifndef MAN_TREE_ITEM_H
#define MAN_TREE_ITEM_H

#include <QStandardItem>

#define     CM_TREE_ROOT            "ROOT"
#define     CM_TREE_SLOT            "SLOT"
#define     CM_TREE_TOKEN           "TOKEN"
#define     CM_TREE_MECHANISM       "MECHANISM"
#define     CM_TREE_SESSION         "SESSION"
#define     CM_TREE_OBJECTS         "OBJECTS"
#define     CM_TREE_CERTIFICATE     "CERTIFICATE"
#define     CM_TREE_PUBLICKEY       "PUBLICKEY"
#define     CM_TREE_PRIVATEKEY      "PRIVATEKEY"
#define     CM_TREE_SECRETKEY       "SECRETKEY"
#define     CM_TREE_DATA            "DATA"

class ManTreeItem : public QStandardItem
{
public:
    ManTreeItem();
    ManTreeItem( const QString& text );


    int getType() { return type_; };
    int getStatus() { return status_; };

    void setType( int type );
    void setStatus( int status );


private:
    int     type_;
    int     status_;
};

#endif // MAN_TREE_ITEM_H
