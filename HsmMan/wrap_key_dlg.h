#ifndef WRAP_KEY_DLG_H
#define WRAP_KEY_DLG_H

#include <QDialog>
#include "ui_wrap_key_dlg.h"

namespace Ui {
class WrapKeyDlg;
}

class WrapKeyDlg : public QDialog, public Ui::WrapKeyDlg
{
    Q_OBJECT

public:
    explicit WrapKeyDlg(QWidget *parent = nullptr);
    ~WrapKeyDlg();

private:

};

#endif // WRAP_KEY_DLG_H
