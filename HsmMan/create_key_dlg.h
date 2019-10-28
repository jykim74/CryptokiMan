#ifndef CREATE_KEY_DLG_H
#define CREATE_KEY_DLG_H

#include <QDialog>
#include "ui_create_key_dlg.h"

namespace Ui {
class CreateKeyDlg;
}

class CreateKeyDlg : public QDialog, public Ui::CreateKeyDlg
{
    Q_OBJECT

public:
    explicit CreateKeyDlg(QWidget *parent = nullptr);
    ~CreateKeyDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void slotChanged( int index );

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

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();
};

#endif // CREATE_KEY_DLG_H
