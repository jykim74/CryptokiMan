#ifndef MAN_TREE_MODEL_H
#define MAN_TREE_MODEL_H

#include "js_pkcs11.h"

#include <QStandardItemModel>
#include <QTableWidget>


class ManTreeItem;

class ManTreeModel : public QStandardItemModel
{
public:
    ManTreeModel( QObject *parent = nullptr );
    JSP11_CTX* getP11CTX() { return p11_ctx_; };
    void setP11CTX( JSP11_CTX *pCTX );

    void showGetInfo();
    void showSlotInfo();

    void setRightTable( QTableWidget *right_table );
    void removeAllRightTable();

private:
    void initialize();

    JSP11_CTX *p11_ctx_;
    QTableWidget    *right_table_;

};

#endif // MAN_TREE_MODEL_H
