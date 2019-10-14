#ifndef SIGN_DLG_H
#define SIGN_DLG_H

#include <QDialog>
#include "ui_sign_dlg.h"

namespace Ui {
class SignDlg;
}

class SignDlg : public QDialog, public Ui::SignDlg
{
    Q_OBJECT

public:
    explicit SignDlg(QWidget *parent = nullptr);
    ~SignDlg();

private:

};

#endif // SIGN_DLG_H
