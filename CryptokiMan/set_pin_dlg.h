/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SET_PIN_DLG_H
#define SET_PIN_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_set_pin_dlg.h"

namespace Ui {
class SetPinDlg;
}

class SetPinDlg : public QDialog, public Ui::SetPinDlg
{
    Q_OBJECT

public:
    explicit SetPinDlg(QWidget *parent = nullptr);
    ~SetPinDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    virtual void accept();

private:
    void initialize();

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // SET_PIN_DLG_H
