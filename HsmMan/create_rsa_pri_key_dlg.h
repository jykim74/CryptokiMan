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

private slots:
    void showEvent(QShowEvent *event);
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

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
};

#endif // GEN_RSA_PRI_KEY_DLG_H
