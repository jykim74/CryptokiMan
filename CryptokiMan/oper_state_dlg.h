/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef OPER_STATE_DLG_H
#define OPER_STATE_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_oper_state_dlg.h"

namespace Ui {
class OperStateDlg;
}

class OperStateDlg : public QDialog, public Ui::OperStateDlg
{
    Q_OBJECT

public:
    explicit OperStateDlg(QWidget *parent = nullptr);
    ~OperStateDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    void clickGetFunctionStatus();
    void clickCancelFunction();
    void clickGetOperationState();
    void clickSetOperationState();
    void changeOperationState();

private:
    void initUI();
    void initialize();

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // OPER_STATE_DLG_H
