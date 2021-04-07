#ifndef GEN_RSA_PRI_KEY_DLG_H
#define GEN_RSA_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_create_rsa_pri_key_dlg.h"

namespace Ui {
class CreateRSAPriKeyDlg;
}

class CreateRSAPriKeyDlg : public QDialog, public Ui::CreateRSAPriKeyDlg
{
    Q_OBJECT

public:
    explicit CreateRSAPriKeyDlg(QWidget *parent = nullptr);
    ~CreateRSAPriKeyDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void clickPrivate();
    void clickDecrypt();
    void clickSign();
    void clickUnwrap();
    void clickModifiable();
    void clickSensitive();
    void clickDerive();
    void clickExtractable();
    void clickToken();
    void clickStartDate();
    void clickEndDate();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();
};

#endif // GEN_RSA_PRI_KEY_DLG_H
