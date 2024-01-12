#ifndef EDIT_ATTRIBUTE_LIST_DLG_H
#define EDIT_ATTRIBUTE_LIST_DLG_H

#include <QDialog>
#include "ui_edit_attribute_list_dlg.h"

namespace Ui {
class EditAttributeListDlg;
}

class EditAttributeListDlg : public QDialog, public Ui::EditAttributeListDlg
{
    Q_OBJECT

public:
    explicit EditAttributeListDlg(QWidget *parent = nullptr);
    ~EditAttributeListDlg();

private:

};

#endif // EDIT_ATTRIBUTE_LIST_DLG_H
