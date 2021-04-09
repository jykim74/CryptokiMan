#ifndef MAN_TREE_MODEL_H
#define MAN_TREE_MODEL_H

#include "js_pkcs11.h"

#include <QStandardItemModel>
#include <QTableWidget>

enum { ATTR_VAL_BOOL, ATTR_VAL_STRING, ATTR_VAL_HEX, ATTR_VAL_KEY_NAME, ATTR_VAL_LEN, ATTR_VAL_DATE };

class ManTreeItem;

class ManTreeModel : public QStandardItemModel
{
public:
    ManTreeModel( QObject *parent = nullptr );

private:
    void initialize();
};

#endif // MAN_TREE_MODEL_H
