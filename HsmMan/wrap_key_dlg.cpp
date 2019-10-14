#include "wrap_key_dlg.h"
#include "ui_wrap_key_dlg.h"

WrapKeyDlg::WrapKeyDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::WrapKeyDlg)
{
    ui->setupUi(this);
}

WrapKeyDlg::~WrapKeyDlg()
{
    delete ui;
}
