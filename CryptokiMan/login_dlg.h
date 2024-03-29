/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef LOGIN_DLG_H
#define LOGIN_DLG_H

#include <QDialog>
#include "ui_login_dlg.h"

namespace Ui {
class LoginDlg;
}

class LoginDlg : public QDialog, public Ui::LoginDlg
{
    Q_OBJECT

public:
    explicit LoginDlg(QWidget *parent = nullptr);
    ~LoginDlg();
    void setSelectedSlot( int index );

private slots:
    void clickLogin();
    void slotChanged( int index );

private:
    void initialize();

};

#endif // LOGIN_DLG_H
