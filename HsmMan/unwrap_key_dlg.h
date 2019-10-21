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

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void slotChanged( int index );

    void unwrapLabelChanged(int index);
    void clickFind();

private:
    void initialize();
    void initUI();
    void setUnwrapLabelList();

};

#endif // UNWRAP_KEY_DLG_H
