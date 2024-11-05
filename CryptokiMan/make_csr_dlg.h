#ifndef MAKE_CSR_DLG_H
#define MAKE_CSR_DLG_H

#include <QDialog>
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

    void setSelectedSlot( int index );

    void setPriObject( CK_OBJECT_HANDLE hPriObj );
    void setSession( CK_SESSION_HANDLE hSession );

    const QString getDN();
    const QString getCSRHex();

private slots:
    void slotChanged( int index );

    void clickOK();
    void clickClear();

    void changePriLabel( int index );
    void changePubLabel( int index );

    int getPriCombo();
    int getPubCombo();


private:
    void initUI();
    void initialize();


    int slot_index_;
    BIN csr_;
    CK_SESSION_HANDLE session_;
};

#endif // MAKE_CSR_DLG_H
