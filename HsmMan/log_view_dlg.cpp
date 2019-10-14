#include "log_view_dlg.h"
#include "ui_log_view_dlg.h"

LogViewDlg::LogViewDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::LogViewDlg)
{
    ui->setupUi(this);
}

LogViewDlg::~LogViewDlg()
{
    delete ui;
}
