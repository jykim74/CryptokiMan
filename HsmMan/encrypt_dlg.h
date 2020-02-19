#ifndef ENCRYPT_DLG_H
#define ENCRYPT_DLG_H

#include <QDialog>
#include "ui_encrypt_dlg.h"

namespace Ui {
class EncryptDlg;
}

class EncryptDlg : public QDialog, public Ui::EncryptDlg
{
    Q_OBJECT

public:
    explicit EncryptDlg(QWidget *parent = nullptr);
    ~EncryptDlg();
    void setSelectedSlot( int index );

private slots:
    void slotChanged( int index );

    void clickInit();
    void clickUpdate();
    void clickFinal();
    void clickEncrypt();
    void clickClose();

    void keyTypeChanged( int index );
    void labelChanged( int index );

private:
    void initialize();
    void initUI();
};

#endif // ENCRYPT_DLG_H
