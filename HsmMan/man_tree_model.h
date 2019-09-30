#ifndef MAN_TREE_MODEL_H
#define MAN_TREE_MODEL_H

#include <QStandardItemModel>

class ManTreeModel : public QStandardItemModel
{
public:
    ManTreeModel( QObject *parent = nullptr );
};

#endif // MAN_TREE_MODEL_H
