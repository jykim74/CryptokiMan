#ifndef CREATE_PQC_PRI_KEY_DLG_H
#define CREATE_PQC_PRI_KEY_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_create_pqc_pri_key_dlg.h"
#include "js_bin.h"

namespace Ui {
class CreatePQCPriKeyDlg;
}

class CreatePQCPriKeyDlg : public QDialog, public Ui::CreatePQCPriKeyDlg
{
    Q_OBJECT

public:
    explicit CreatePQCPriKeyDlg(QWidget *parent = nullptr);
    ~CreatePQCPriKeyDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    virtual void accept();
    void changeAlg();

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
    void initUI();
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    void setDefaults();
    int getSKI_SPKI( BIN *pSKI, BIN *pSPKI );

    SlotInfo slot_info_;
    int slot_index_ = -1;

};

#endif // CREATE_PQC_PRI_KEY_DLG_H
