/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef GEN_DSA_PUB_KEY_DLG_H
#define GEN_DSA_PUB_KEY_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_create_dsa_pub_key_dlg.h"
#include "js_bin.h"

namespace Ui {
class CreateDSAPubKeyDlg;
}

class CreateDSAPubKeyDlg : public QDialog, public Ui::CreateDSAPubKeyDlg
{
    Q_OBJECT

public:
    explicit CreateDSAPubKeyDlg(QWidget *parent = nullptr);
    ~CreateDSAPubKeyDlg();

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

    void changeP( const QString& text );
    void changeQ( const QString& text );
    void changeG( const QString& text );
    void changePublic( const QString& text );

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    void setDefaults();
    int getSKI( BIN *pSKI );

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // GEN_EC_PUB_KEY_DLG_H
