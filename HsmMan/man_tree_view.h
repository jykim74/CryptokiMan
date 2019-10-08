#ifndef MAN_TREE_VIEW_H
#define MAN_TREE_VIEW_H

#include <QTreeView>
#include <QModelIndex>

class ManTreeItem;

class ManTreeView : public QTreeView
{
    Q_OBJECT
public:
    ManTreeView( QWidget* parent = nullptr );

private slots:
    void onItemClicked( const QModelIndex& index );
    void showContextMenu( QPoint point );

    void P11Initialize();
    void P11Finalize();

private:
    ManTreeItem* currentItem();
};

#endif // MAN_TREE_VIEW_H
