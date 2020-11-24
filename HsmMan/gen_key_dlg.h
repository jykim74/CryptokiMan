#ifndef GEN_KEY_DLG_H
#define GEN_KEY_DLG_H

#include <QDialog>
#include "ui_gen_key_dlg.h"

namespace Ui {
class GenKeyDlg;
}

class GenKeyDlg : public QDialog, public Ui::GenKeyDlg
{
    Q_OBJECT

public:
    explicit GenKeyDlg(QWidget *parent = nullptr);
    ~GenKeyDlg();
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
    void clickStartDate();
    void clickEndDate();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();
};

#endif // GEN_KEY_DLG_H
