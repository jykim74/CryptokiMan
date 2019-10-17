#ifndef GEN_EC_PRI_KEY_DLG_H
#define GEN_EC_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_create_ec_pri_key_dlg.h"

namespace Ui {
class CreateECPriKeyDlg;
}

class CreateECPriKeyDlg : public QDialog, public Ui::CreateECPriKeyDlg
{
    Q_OBJECT

public:
    explicit CreateECPriKeyDlg(QWidget *parent = nullptr);
    ~CreateECPriKeyDlg();

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

#endif // GEN_EC_PRI_KEY_DLG_H
