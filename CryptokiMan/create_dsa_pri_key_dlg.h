/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef GEN_DSA_PRI_KEY_DLG_H
#define GEN_DSA_PRI_KEY_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_create_dsa_pri_key_dlg.h"
#include "js_bin.h"

namespace Ui {
class CreateDSAPriKeyDlg;
}

class CreateDSAPriKeyDlg : public QDialog, public Ui::CreateDSAPriKeyDlg
{
    Q_OBJECT

public:
    explicit CreateDSAPriKeyDlg(QWidget *parent = nullptr);
    ~CreateDSAPriKeyDlg();

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

    void changeP( const QString& text );
    void changeQ( const QString& text );
    void changeG( const QString& text );
    void changeKeyValue( const QString& text );
private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    void setDefaults();
    int getSKI_SPKI( BIN *pSKI, BIN *pSPKI );

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // GEN_EC_PRI_KEY_DLG_H
