#ifndef MAN_TREE_VIEW_H
#define MAN_TREE_VIEW_H

#include <QTreeView>

class ManTreeView : public QTreeView
{
    Q_OBJECT
public:
    ManTreeView( QWidget* parent = nullptr );
};

#endif // MAN_TREE_VIEW_H
