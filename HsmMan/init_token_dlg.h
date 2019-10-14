#ifndef INIT_TOKEN_DLG_H
#define INIT_TOKEN_DLG_H

#include <QDialog>

namespace Ui {
class InitTokenDlg;
}

class InitTokenDlg : public QDialog
{
    Q_OBJECT

public:
    explicit InitTokenDlg(QWidget *parent = nullptr);
    ~InitTokenDlg();

private:
    Ui::InitTokenDlg *ui;
};

#endif // INIT_TOKEN_DLG_H
