#ifndef UNWRAP_KEY_DLG_H
#define UNWRAP_KEY_DLG_H

#include <QDialog>

namespace Ui {
class UnwrapKeyDlg;
}

class UnwrapKeyDlg : public QDialog
{
    Q_OBJECT

public:
    explicit UnwrapKeyDlg(QWidget *parent = nullptr);
    ~UnwrapKeyDlg();

private:
    Ui::UnwrapKeyDlg *ui;
};

#endif // UNWRAP_KEY_DLG_H
