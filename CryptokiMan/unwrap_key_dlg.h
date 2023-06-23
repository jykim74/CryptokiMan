#ifndef UNWRAP_KEY_DLG_H
#define UNWRAP_KEY_DLG_H

#include <QDialog>
#include "ui_unwrap_key_dlg.h"

namespace Ui {
class UnwrapKeyDlg;
}

class UnwrapKeyDlg : public QDialog, public Ui::UnwrapKeyDlg
{
    Q_OBJECT

public:
    explicit UnwrapKeyDlg(QWidget *parent = nullptr);
    ~UnwrapKeyDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void unwrapLabelChanged(int index);
    void unwrapTypeChanged(int index);
    void classChanged(int index);
    void clickFind();

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

    void changeUnwrapParam( const QString& text );
private:
    void initUI();
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();

    void setUnwrapSecretLabel();
    void setUnwrapRSAPrivateLabel();

    int slot_index_;
    long session_;
};

#endif // UNWRAP_KEY_DLG_H
