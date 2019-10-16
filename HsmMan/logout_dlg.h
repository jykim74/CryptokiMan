#ifndef LOGOUT_DLG_H
#define LOGOUT_DLG_H

#include <QDialog>
#include "ui_logout_dlg.h"

namespace Ui {
class LogoutDlg;
}

class LogoutDlg : public QDialog, public Ui::LogoutDlg
{
    Q_OBJECT

public:
    explicit LogoutDlg(QWidget *parent = nullptr);
    ~LogoutDlg();

private:

};

#endif // LOGOUT_DLG_H
