/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef GEN_DATA_DLG_H
#define GEN_DATA_DLG_H

#include <QDialog>
#include "js_bin.h"
#include "slot_info.h"
#include "ui_create_data_dlg.h"

namespace Ui {
class CreateDataDlg;
}

class CreateDataDlg : public QDialog, public Ui::CreateDataDlg
{
    Q_OBJECT

public:
    explicit CreateDataDlg(QWidget *parent = nullptr);
    ~CreateDataDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    virtual void accept();

    void clickPrivate();
    void clickModifiable();
    void clickCopyable();
    void clickDestroyable();
    void clickToken();

    void changeData();
    void changeObjectID();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // GEN_DATA_DLG_H
