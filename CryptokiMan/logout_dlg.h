/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef LOGOUT_DLG_H
#define LOGOUT_DLG_H

#include <QDialog>
#include "slot_info.h"
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
    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    virtual void accept();

private:
    void initialize();
    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // LOGOUT_DLG_H
