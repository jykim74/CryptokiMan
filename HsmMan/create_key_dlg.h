#ifndef CREATE_KEY_DLG_H
#define CREATE_KEY_DLG_H

#include <QDialog>
#include "ui_create_key_dlg.h"

namespace Ui {
class CreateKeyDlg;
}

class CreateKeyDlg : public QDialog, public Ui::CreateKeyDlg
{
    Q_OBJECT

public:
    explicit CreateKeyDlg(QWidget *parent = nullptr);
    ~CreateKeyDlg();

private:

};

#endif // CREATE_KEY_DLG_H
