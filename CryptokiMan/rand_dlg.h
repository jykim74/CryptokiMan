/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef RAND_DLG_H
#define RAND_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_rand_dlg.h"

namespace Ui {
class RandDlg;
}

class RandDlg : public QDialog, public Ui::RandDlg
{
    Q_OBJECT

public:
    explicit RandDlg(QWidget *parent = nullptr);
    ~RandDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    void clickSeed();
    void clickGenRand();

    void clickSeedClear();
    void clickRandClear();

    void changeSeed();
    void changeOutput();
private:
    void initialize();
    void initUI();

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // RAND_DLG_H
