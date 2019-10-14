#ifndef SET_PIN_DLG_H
#define SET_PIN_DLG_H

#include <QDialog>
#include "ui_set_pin_dlg.h"

namespace Ui {
class SetPinDlg;
}

class SetPinDlg : public QDialog, public Ui::SetPinDlg
{
    Q_OBJECT

public:
    explicit SetPinDlg(QWidget *parent = nullptr);
    ~SetPinDlg();

private:
};

#endif // SET_PIN_DLG_H
