#include "init_token_dlg.h"
#include "ui_init_token_dlg.h"

InitTokenDlg::InitTokenDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::InitTokenDlg)
{
    ui->setupUi(this);
}

InitTokenDlg::~InitTokenDlg()
{
    delete ui;
}
