/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef GEN_EC_PUB_KEY_DLG_H
#define GEN_EC_PUB_KEY_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_create_ec_pub_key_dlg.h"
#include "js_bin.h"

namespace Ui {
class CreateECPubKeyDlg;
}

class CreateECPubKeyDlg : public QDialog, public Ui::CreateECPubKeyDlg
{
    Q_OBJECT

public:
    explicit CreateECPubKeyDlg( bool bED = false, QWidget *parent = nullptr);
    ~CreateECPubKeyDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    virtual void accept();

    void clickGenKey();
    void clickFindKey();
    void clickUseSKI();
    void clickPrivate();
    void clickEncrypt();
    void clickWrap();
    void clickVerify();
    void clickVerifyRecover();
    void clickDerive();
    void clickModifiable();
    void clickCopyable();
    void clickDestroyable();
    void clickToken();
    void clickTrusted();
    void clickStartDate();
    void clickEndDate();

    void changeECPoints( const QString& text );
    void changeECParams( const QString& text );
private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    void setDefaults();
    int getSKI( BIN *pSKI );
    bool is_ed_;

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // GEN_EC_PUB_KEY_DLG_H
