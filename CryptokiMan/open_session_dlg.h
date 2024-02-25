/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef OPEN_SESSION_DLG_H
#define OPEN_SESSION_DLG_H

#include <QDialog>
#include "ui_open_session_dlg.h"

namespace Ui {
class OpenSessionDlg;
}

class OpenSessionDlg : public QDialog, public Ui::OpenSessionDlg
{
    Q_OBJECT

public:
    explicit OpenSessionDlg(QWidget *parent = nullptr);
    ~OpenSessionDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();

    void clickOpenSession();
    void clickWaitForSlotEvent();

private:
    void initialize();
};

#endif // OPEN_SESSION_DLG_H
