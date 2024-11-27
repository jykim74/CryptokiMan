/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef WRAP_KEY_DLG_H
#define WRAP_KEY_DLG_H

#include <QDialog>
#include "ui_wrap_key_dlg.h"

namespace Ui {
class WrapKeyDlg;
}

class WrapKeyDlg : public QDialog, public Ui::WrapKeyDlg
{
    Q_OBJECT

public:
    explicit WrapKeyDlg(QWidget *parent = nullptr);
    ~WrapKeyDlg();
    void setSelectedSlot( int index );

private slots:
    void clickWrapKey();
    void slotChanged( int index );

    void wrappingTypeChanged( int index );
    void wrappingMechChanged( int index );
    void clickSaveFile();
    void clickClearOutput();
    void changeOutput();
    void typeChanged( int index );

    void changeWrappingParam(const QString& text );
    void clickWrappingSelect();
    void clickSelect();
private:
    void initialize();
    void initUI();

    int slot_index_;
    long session_;
};

#endif // WRAP_KEY_DLG_H
