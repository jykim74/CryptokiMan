#ifndef GEN_RSA_PUB_KEY_DLG_H
#define GEN_RSA_PUB_KEY_DLG_H

#include <QDialog>
#include "ui_create_rsa_pub_key_dlg.h"

namespace Ui {
class CreateRSAPubKeyDlg;
}

class CreateRSAPubKeyDlg : public QDialog, public Ui::CreateRSAPubKeyDlg
{
    Q_OBJECT

public:
    explicit CreateRSAPubKeyDlg(QWidget *parent = nullptr);
    ~CreateRSAPubKeyDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void slotChanged( int index );

    void clickPrivate();
    void clickEncrypt();
    void clickWrap();
    void clickVerify();
    void clickDerive();
    void clickModifiable();
    void clickToken();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

};

#endif // GEN_RSA_PUB_KEY_DLG_H
