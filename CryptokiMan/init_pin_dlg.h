/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef INIT_PIN_DLG_H
#define INIT_PIN_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_init_pin_dlg.h"

namespace Ui {
class InitPinDlg;
}

class InitPinDlg : public QDialog, public Ui::InitPinDlg
{
    Q_OBJECT

public:
    explicit InitPinDlg(QWidget *parent = nullptr);
    ~InitPinDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    virtual void accept();

private:
    void initialize();

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // INIT_PIN_DLG_H
