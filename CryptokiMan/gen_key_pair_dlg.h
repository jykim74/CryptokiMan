/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef GEN_KEY_PAIR_DLG_H
#define GEN_KEY_PAIR_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_gen_key_pair_dlg.h"

namespace Ui {
class GenKeyPairDlg;
}

class GenKeyPairDlg : public QDialog, public Ui::GenKeyPairDlg
{
    Q_OBJECT

public:
    explicit GenKeyPairDlg(QWidget *parent = nullptr);
    ~GenKeyPairDlg();
    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    virtual void accept();
    void mechChanged( int nIndex );

    void clickPriSameLabel();
    void clickPubSameLabel();

    void clickPriUseSKI();
    void clickPriUseSPKI();

    void clickPriPrivate();
    void clickPriDecrypt();
    void clickPriSign();
    void clickPriSignRecover();
    void clickPriUnwrap();
    void clickPriModifiable();
    void clickPriCopyable();
    void clickPriDestroyable();
    void clickPriSensitive();
    void clickPriDerive();
    void clickPriExtractable();
    void clickPriToken();
    void clickPriStartDate();
    void clickPriEndDate();

    void clickPubUseSKI();

    void clickPubPrivate();
    void clickPubEncrypt();
    void clickPubWrap();
    void clickPubVerify();
    void clickPubVerifyRecover();
    void clickPubDerive();
    void clickPubModifiable();
    void clickPubCopyable();
    void clickPubDestroyable();
    void clickPubToken();
    void clickPubTrusted();
    void clickPubStartDate();
    void clickPubEndDate();
    void clickGenDHParam();
    void changeDH_P();

    void clickGenDSAParam();
    void clickClearDSAParam();
    void clickExportDHParam();
    void clickClearDHParam();
    void changeDSA_P();
    void changeDSA_G();
    void changeDSA_Q();

private:
    void initUI();
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();

    int setSKI_SPKI( long hSession, int nKeyType, long hPri, long hPub );

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // GEN_KEY_PAIR_DLG_H
