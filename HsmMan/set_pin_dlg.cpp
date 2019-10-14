#include "set_pin_dlg.h"
#include "ui_set_pin_dlg.h"

SetPinDlg::SetPinDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SetPinDlg)
{
    ui->setupUi(this);
}

SetPinDlg::~SetPinDlg()
{
    delete ui;
}
