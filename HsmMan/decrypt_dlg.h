#ifndef DECRYPT_DLG_H
#define DECRYPT_DLG_H

#include <QDialog>
#include "ui_decrypt_dlg.h"

namespace Ui {
class DecryptDlg;
}

class DecryptDlg : public QDialog, public Ui::DecryptDlg
{
    Q_OBJECT

public:
    explicit DecryptDlg(QWidget *parent = nullptr);
    ~DecryptDlg();

private slots:
    void showEvent(QShowEvent *event);
    void slotChanged( int index );

    void clickInit();
    void clickUpdate();
    void clickFinal();
    void clickDecrypt();
    void clickClose();

    void keyTypeChanged( int index );
    void labelChanged( int index );

private:
    void initialize();
    void initUI();

};

#endif // DECRYPT_DLG_H
