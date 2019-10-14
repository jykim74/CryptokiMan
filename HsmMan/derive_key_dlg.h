#ifndef DERIVE_KEY_DLG_H
#define DERIVE_KEY_DLG_H

#include <QDialog>

namespace Ui {
class DeriveKeyDlg;
}

class DeriveKeyDlg : public QDialog
{
    Q_OBJECT

public:
    explicit DeriveKeyDlg(QWidget *parent = nullptr);
    ~DeriveKeyDlg();

private:
    Ui::DeriveKeyDlg *ui;
};

#endif // DERIVE_KEY_DLG_H
