#ifndef SECRET_INFO_DLG_H
#define SECRET_INFO_DLG_H

#include <QDialog>
#include "ui_secret_info_dlg.h"

namespace Ui {
class SecretInfoDlg;
}

class SecretInfoDlg : public QDialog, public Ui::SecretInfoDlg
{
    Q_OBJECT

public:
    explicit SecretInfoDlg(QWidget *parent = nullptr);
    ~SecretInfoDlg();

    void setHandle( long session_, long hObj );

private slots:
    void showEvent(QShowEvent *event);
    void changeKey();
    void changeID();

private:
    void initialize();

    long handle_;
    long session_;
};

#endif // SECRET_INFO_DLG_H
