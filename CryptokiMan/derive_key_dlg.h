#ifndef DERIVE_KEY_DLG_H
#define DERIVE_KEY_DLG_H

#include <QDialog>
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
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void srcLabelChanged( int index );
    void classChanged( int index );

    void clickPrivate();
    void clickSensitive();
    void clickWrap();
    void clickUnwrap();
    void clickEncrypt();
    void clickDecrypt();
    void clickModifiable();
    void clickSign();
    void clickVerify();
    void clickToken();
    void clickExtractable();
    void clickDerive();
    void clickStartDate();
    void clickEndDate();

    void changeMechanism( int index );

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setSrcLabelList();

    void setDefaults();
    void setMechanism( void *pMech );
    void freeMechanism( void *pMech );

    int slot_index_;
    int session_;
};

#endif // DERIVE_KEY_DLG_H
