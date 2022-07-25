#ifndef DEL_OBJECT_DLG_H
#define DEL_OBJECT_DLG_H

#include <QDialog>
#include "ui_del_object_dlg.h"

namespace Ui {
class DelObjectDlg;
}

class DelObjectDlg : public QDialog, public Ui::DelObjectDlg
{
    Q_OBJECT

public:
    explicit DelObjectDlg(QWidget *parent = nullptr);
    ~DelObjectDlg();
    void setSlotIndex( int index );
    void setObjectIndex( int index );
    void setObjectID( long id );

private slots:
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *);

    void deleteObj();
    void deleteAllObj();
    void slotChanged( int index );

    void labelChanged( int index );
    void objectChanged( int index );

private:
    void initialize();

    int slot_index_;
    int object_index_;
    long object_id_;
};

#endif // DEL_OBJECT_DLG_H
