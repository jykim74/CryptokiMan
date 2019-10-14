#ifndef IMPORT_CERT_DLG_H
#define IMPORT_CERT_DLG_H

#include <QDialog>
#include "ui_import_cert_dlg.h"

namespace Ui {
class ImportCertDlg;
}

class ImportCertDlg : public QDialog, public Ui::ImportCertDlg
{
    Q_OBJECT

public:
    explicit ImportCertDlg(QWidget *parent = nullptr);
    ~ImportCertDlg();

private:

};

#endif // IMPORT_CERT_DLG_H
