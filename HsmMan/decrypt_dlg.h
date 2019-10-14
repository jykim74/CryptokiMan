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

private:

};

#endif // DECRYPT_DLG_H
