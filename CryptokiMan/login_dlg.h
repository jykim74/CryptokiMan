/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef LOGIN_DLG_H
#define LOGIN_DLG_H

#include <QDialog>
#include "slot_info.h"
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
    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    void clickLogin();

private:
    void initialize();
    SlotInfo slot_info_;
    int slot_index_ = -1;

};

#endif // LOGIN_DLG_H
