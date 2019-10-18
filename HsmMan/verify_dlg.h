#ifndef VERIFY_DLG_H
#define VERIFY_DLG_H

#include <QDialog>
#include "ui_verify_dlg.h"

namespace Ui {
class VerifyDlg;
}

class VerifyDlg : public QDialog, public Ui::VerifyDlg
{
    Q_OBJECT

public:
    explicit VerifyDlg(QWidget *parent = nullptr);
    ~VerifyDlg();

private slots:
    void showEvent(QShowEvent *event);
    void slotChanged( int index );

    void clickInit();
    void clickUpdate();
    void clickFinal();
    void clickVerify();
    void clickClose();

    void keyTypeChanged( int index );
    void labelChanged( int index );

private:
    void initialize();
    void initUI();
};

#endif // VERIFY_DLG_H
