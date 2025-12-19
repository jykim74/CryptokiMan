/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef FIND_OBJECT_DLG_H
#define FIND_OBJECT_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_find_object_dlg.h"

namespace Ui {
class FindObjectDlg;
}

class FindObjectDlg : public QDialog, public Ui::FindObjectDlg
{
    Q_OBJECT

public:
    explicit FindObjectDlg(QWidget *parent = nullptr);
    ~FindObjectDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    void changeClass( int index );
    void changeKeyType( int index );

    void clickPrivate();
    void clickSensitive();
    void clickWrap();
    void clickUnwrap();
    void clickEncrypt();
    void clickDecrypt();
    void clickModifiable();
    void clickCopyable();
    void clickDestroyable();
    void clickSign();
    void clickVerify();
    void clickToken();
    void clickDerive();
    void clickExtractable();
    void clickStartDate();
    void clickEndDate();
    void clickTrusted();

    void clickFindObjects();

private:
    void initUI();
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // FIND_OBJECT_DLG_H
