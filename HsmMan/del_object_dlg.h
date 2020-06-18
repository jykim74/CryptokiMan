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
    void setSeletedSlot( int index );
    void setSelectedObject( int index );


private slots:
    void deleteObj();
    void deleteAllObj();
    void slotChanged( int index );

    void labelChanged( int index );
    void objectChanged( int index );

private:
    void initialize();
};

#endif // DEL_OBJECT_DLG_H
