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

private:

};

#endif // DEL_OBJECT_DLG_H
