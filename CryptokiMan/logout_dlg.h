/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

private:
    void initialize();

};

#endif // LOGOUT_DLG_H
