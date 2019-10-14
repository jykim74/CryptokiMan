#ifndef SET_PIN_DLG_H
#define SET_PIN_DLG_H

#include <QDialog>

namespace Ui {
class SetPinDlg;
}

class SetPinDlg : public QDialog
{
    Q_OBJECT

public:
    explicit SetPinDlg(QWidget *parent = nullptr);
    ~SetPinDlg();

private:
    Ui::SetPinDlg *ui;
};

#endif // SET_PIN_DLG_H
