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
    int currentSlotIndex();

private slots:
    void onItemClicked( const QModelIndex& index );
    void showContextMenu( QPoint point );

public slots:
    void P11Initialize();
    void P11Finalize();
    int showTypeList( int nSlotIndex, int nType );

private:
    ManTreeItem* currentItem();
};

#endif // MAN_TREE_VIEW_H
