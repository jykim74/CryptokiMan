/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef INIT_TOKEN_DLG_H
#define INIT_TOKEN_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_init_token_dlg.h"

namespace Ui {
class InitTokenDlg;
}

class InitTokenDlg : public QDialog, public Ui::InitTokenDlg
{
    Q_OBJECT

public:
    explicit InitTokenDlg(QWidget *parent = nullptr);
    ~InitTokenDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    virtual void accept();

private:
    void initialize();

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // INIT_TOKEN_DLG_H
