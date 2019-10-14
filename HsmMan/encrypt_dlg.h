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

private:

};

#endif // ENCRYPT_DLG_H
