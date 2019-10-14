#include "rand_dlg.h"
#include "ui_rand_dlg.h"

RandDlg::RandDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RandDlg)
{
    ui->setupUi(this);
}

RandDlg::~RandDlg()
{
    delete ui;
}
