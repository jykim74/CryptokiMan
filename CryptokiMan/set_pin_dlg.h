/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SET_PIN_DLG_H
#define SET_PIN_DLG_H

#include <QDialog>
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
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

private:
    void initialize();
};

#endif // SET_PIN_DLG_H
