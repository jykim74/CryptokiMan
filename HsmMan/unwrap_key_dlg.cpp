#include "unwrap_key_dlg.h"
#include "ui_unwrap_key_dlg.h"

UnwrapKeyDlg::UnwrapKeyDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::UnwrapKeyDlg)
{
    ui->setupUi(this);
}

UnwrapKeyDlg::~UnwrapKeyDlg()
{
    delete ui;
}
