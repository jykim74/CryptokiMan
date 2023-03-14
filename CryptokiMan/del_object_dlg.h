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
    void setObjectType( int type );
    void setObjectID( long id );

private slots:
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *);

    void deleteObj();
    void deleteAllObj();

    void slotChanged(int index);
    void labelChanged( int index );
    void objectTypeChanged( int type );

private:
    void initialize();

    int object_type_;
    int slot_index_;
    long object_id_;
    long session_;
};

#endif // DEL_OBJECT_DLG_H
