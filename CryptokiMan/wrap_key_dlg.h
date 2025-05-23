/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef WRAP_KEY_DLG_H
#define WRAP_KEY_DLG_H

#include <QDialog>
#include "slot_info.h"
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

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    void clickWrapKey();

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

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // WRAP_KEY_DLG_H
