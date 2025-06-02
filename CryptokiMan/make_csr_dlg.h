#ifndef MAKE_CSR_DLG_H
#define MAKE_CSR_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_make_csr_dlg.h"
#include "js_pkcs11.h"
#include "js_bin.h"

namespace Ui {
class MakeCSRDlg;
}

class MakeCSRDlg : public QDialog, public Ui::MakeCSRDlg
{
    Q_OBJECT

public:
    explicit MakeCSRDlg(QWidget *parent = nullptr);
    ~MakeCSRDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

    void setPriObject( CK_OBJECT_HANDLE hPriObj );
    void setSession( CK_SESSION_HANDLE hSession );

    const QString getDN();
    const QString getCSRHex();

private slots:
    void clickOK();
    void clickClear();
    void changeDN();

    void changePriLabel( int index );
    void changePubLabel( int index );

    int getPriCombo();
    int getPubCombo();


private:
    void initUI();
    void initialize();


    SlotInfo slot_info_;
    int slot_index_ = -1;

    BIN csr_;
};

#endif // MAKE_CSR_DLG_H
