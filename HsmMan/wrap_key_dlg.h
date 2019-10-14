#ifndef WRAP_KEY_DLG_H
#define WRAP_KEY_DLG_H

#include <QDialog>

namespace Ui {
class WrapKeyDlg;
}

class WrapKeyDlg : public QDialog
{
    Q_OBJECT

public:
    explicit WrapKeyDlg(QWidget *parent = nullptr);
    ~WrapKeyDlg();

private:
    Ui::WrapKeyDlg *ui;
};

#endif // WRAP_KEY_DLG_H
