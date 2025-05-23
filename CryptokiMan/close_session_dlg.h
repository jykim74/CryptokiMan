/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CLOSE_SESSION_DLG_H
#define CLOSE_SESSION_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_close_session_dlg.h"

namespace Ui {
class CloseSessionDlg;
}


class CloseSessionDlg : public QDialog, public Ui::CloseSessionDlg
{
    Q_OBJECT

public:
    explicit CloseSessionDlg(QWidget *parent = nullptr);
    ~CloseSessionDlg();
    void setAll( bool all );
    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    virtual void accept();

private:
    void initialize();
    bool     all_;
    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // CLOSE_SESSION_DLG_H
