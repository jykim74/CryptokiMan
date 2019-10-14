#include "derive_key_dlg.h"
#include "ui_derive_key_dlg.h"

DeriveKeyDlg::DeriveKeyDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DeriveKeyDlg)
{
    ui->setupUi(this);
}

DeriveKeyDlg::~DeriveKeyDlg()
{
    delete ui;
}
