/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef DERIVE_KEY_DLG_H
#define DERIVE_KEY_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_derive_key_dlg.h"
#include "js_bin.h"

namespace Ui {
class DeriveKeyDlg;
}

class DeriveKeyDlg : public QDialog, public Ui::DeriveKeyDlg
{
    Q_OBJECT

public:
    explicit DeriveKeyDlg(QWidget *parent = nullptr);
    ~DeriveKeyDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    virtual void accept();

    void classChanged( int index );
    void typeChanged( int index );

    void clickSelectSrcKey();

    void clickUseRand();
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
    void clickSignRecover();
    void clickVerify();
    void clickVerifyRecover();
    void clickToken();
    void clickTrusted();
    void clickExtractable();
    void clickDerive();
    void clickStartDate();
    void clickEndDate();

    void changeMechanism( int index );
    void changeParam1( const QString& text );
    void changeParam2( const QString& text );

private:
    void initUI();
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    void setDefaults();
    void setMechanism( void *pMech );
    void freeMechanism( void *pMech );

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // DERIVE_KEY_DLG_H
