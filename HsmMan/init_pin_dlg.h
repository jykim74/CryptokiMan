#ifndef INIT_PIN_DLG_H
#define INIT_PIN_DLG_H

#include <QDialog>

namespace Ui {
class InitPinDlg;
}

class InitPinDlg : public QDialog
{
    Q_OBJECT

public:
    explicit InitPinDlg(QWidget *parent = nullptr);
    ~InitPinDlg();

private:
    Ui::InitPinDlg *ui;
};

#endif // INIT_PIN_DLG_H
