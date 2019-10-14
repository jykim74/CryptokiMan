#include "init_pin_dlg.h"
#include "ui_init_pin_dlg.h"

InitPinDlg::InitPinDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::InitPinDlg)
{
    ui->setupUi(this);
}

InitPinDlg::~InitPinDlg()
{
    delete ui;
}
