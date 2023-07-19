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
    void setSelectedSlot( int index );

private slots:
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
    void clickExtractable();
    void clickDerive();
    void clickStartDate();
    void clickEndDate();

    void changeKey();
private:
    void initUI();
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();
};

#endif // CREATE_KEY_DLG_H
