#ifndef DERIVE_KEY_DLG_H
#define DERIVE_KEY_DLG_H

#include <QDialog>
#include "ui_derive_key_dlg.h"

namespace Ui {
class DeriveKeyDlg;
}

class DeriveKeyDlg : public QDialog, public Ui::DeriveKeyDlg
{
    Q_OBJECT

public:
    explicit DeriveKeyDlg(QWidget *parent = nullptr);
    ~DeriveKeyDlg();

private:

};

#endif // DERIVE_KEY_DLG_H
