#ifndef GEN_EC_PUB_KEY_DLG_H
#define GEN_EC_PUB_KEY_DLG_H

#include <QDialog>
#include "ui_create_ec_pub_key_dlg.h"

namespace Ui {
class CreateECPubKeyDlg;
}

class CreateECPubKeyDlg : public QDialog, public Ui::CreateECPubKeyDlg
{
    Q_OBJECT

public:
    explicit CreateECPubKeyDlg(QWidget *parent = nullptr);
    ~CreateECPubKeyDlg();

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

#endif // GEN_EC_PUB_KEY_DLG_H
