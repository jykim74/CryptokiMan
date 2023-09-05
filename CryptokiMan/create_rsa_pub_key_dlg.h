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
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void clickPrivate();
    void clickEncrypt();
    void clickWrap();
    void clickVerify();
    void clickVerifyRecover();
    void clickDerive();
    void clickModifiable();
    void clickToken();
    void clickStartDate();
    void clickEndDate();

    void changeModules( const QString& text );
private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();
};

#endif // GEN_RSA_PUB_KEY_DLG_H
