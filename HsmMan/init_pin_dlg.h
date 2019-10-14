#ifndef INIT_PIN_DLG_H
#define INIT_PIN_DLG_H

#include <QDialog>
#include "ui_init_pin_dlg.h"

namespace Ui {
class InitPinDlg;
}

class InitPinDlg : public QDialog, public Ui::InitPinDlg
{
    Q_OBJECT

public:
    explicit InitPinDlg(QWidget *parent = nullptr);
    ~InitPinDlg();

private:

};

#endif // INIT_PIN_DLG_H
