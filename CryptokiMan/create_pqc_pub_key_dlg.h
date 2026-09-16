#ifndef CREATE_PQC_PUB_KEY_DLG_H
#define CREATE_PQC_PUB_KEY_DLG_H

#include <QDialog>
#include "ui_create_pqc_pub_key_dlg.h"
#include "slot_info.h"
#include "js_bin.h"

namespace Ui {
class CreatePQCPubKeyDlg;
}

class CreatePQCPubKeyDlg : public QDialog, public Ui::CreatePQCPubKeyDlg
{
    Q_OBJECT

public:
    explicit CreatePQCPubKeyDlg(QWidget *parent = nullptr);
    ~CreatePQCPubKeyDlg();

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

#endif // CREATE_PQC_PUB_KEY_DLG_H
