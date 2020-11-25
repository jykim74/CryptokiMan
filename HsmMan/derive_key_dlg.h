#ifndef DERIVE_KEY_DLG_H
#define DERIVE_KEY_DLG_H

#include <QDialog>
#include "ui_derive_key_dlg.h"

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
    void clickStartDate();
    void clickEndDate();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setSrcLabelList();

    void setDefaults();
};

#endif // DERIVE_KEY_DLG_H
