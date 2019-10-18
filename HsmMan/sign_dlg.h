#ifndef SIGN_DLG_H
#define SIGN_DLG_H

#include <QDialog>
#include "ui_sign_dlg.h"

namespace Ui {
class SignDlg;
}

class SignDlg : public QDialog, public Ui::SignDlg
{
    Q_OBJECT

public:
    explicit SignDlg(QWidget *parent = nullptr);
    ~SignDlg();

private slots:
    void showEvent(QShowEvent *event);
    void slotChanged( int index );

    void clickInit();
    void clickUpdate();
    void clickFinal();
    void clickSign();
    void clickClose();

    void keyTypeChanged( int index );
    void labelChanged( int index );

private:
    void initialize();
    void initUI();
};

#endif // SIGN_DLG_H
