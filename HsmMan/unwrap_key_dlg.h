#ifndef UNWRAP_KEY_DLG_H
#define UNWRAP_KEY_DLG_H

#include <QDialog>
#include "ui_unwrap_key_dlg.h"

namespace Ui {
class UnwrapKeyDlg;
}

class UnwrapKeyDlg : public QDialog, public Ui::UnwrapKeyDlg
{
    Q_OBJECT

public:
    explicit UnwrapKeyDlg(QWidget *parent = nullptr);
    ~UnwrapKeyDlg();

private:

};

#endif // UNWRAP_KEY_DLG_H
