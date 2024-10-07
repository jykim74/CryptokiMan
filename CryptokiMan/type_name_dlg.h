#ifndef TYPE_NAME_DLG_H
#define TYPE_NAME_DLG_H

#include <QDialog>
#include "ui_type_name_dlg.h"

namespace Ui {
class TypeNameDlg;
}

class TypeNameDlg : public QDialog, public Ui::TypeNameDlg
{
    Q_OBJECT

public:
    explicit TypeNameDlg(QWidget *parent = nullptr);
    ~TypeNameDlg();

private slots:
    void clickClear();
    void clickSearch();

private:

};

#endif // TYPE_NAME_DLG_H
