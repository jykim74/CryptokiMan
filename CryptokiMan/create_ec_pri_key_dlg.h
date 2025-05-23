/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef GEN_EC_PRI_KEY_DLG_H
#define GEN_EC_PRI_KEY_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_create_ec_pri_key_dlg.h"
#include "js_bin.h"

namespace Ui {
class CreateECPriKeyDlg;
}

class CreateECPriKeyDlg : public QDialog, public Ui::CreateECPriKeyDlg
{
    Q_OBJECT

public:
    explicit CreateECPriKeyDlg(bool bED = false, QWidget *parent = nullptr);
    ~CreateECPriKeyDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    virtual void accept();

    void clickGenKey();
    void clickFindKey();

    void clickUseSKI();
    void clickUseSPKI();

    void clickPrivate();
    void clickDecrypt();
    void clickSign();
    void clickSignRecover();
    void clickUnwrap();
    void clickModifiable();
    void clickCopyable();
    void clickDestroyable();
    void clickSensitive();
    void clickDerive();
    void clickExtractable();
    void clickToken();
    void clickStartDate();
    void clickEndDate();

    void changeECParams( const QString& text );
    void changeKeyValue( const QString& text );
private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    void setDefaults();
    int getSKI_SPKI( BIN *pSKI, BIN *pSPKI );

    bool is_ed_;

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // GEN_EC_PRI_KEY_DLG_H
