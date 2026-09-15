#ifndef CREATE_PQC_PRI_KEY_DLG_H
#define CREATE_PQC_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_create_pqc_pri_key_dlg.h"

namespace Ui {
class CreatePQCPriKeyDlg;
}

class CreatePQCPriKeyDlg : public QDialog, public Ui::CreatePQCPriKeyDlg
{
    Q_OBJECT

public:
    explicit CreatePQCPriKeyDlg(QWidget *parent = nullptr);
    ~CreatePQCPriKeyDlg();

private:

};

#endif // CREATE_PQC_PRI_KEY_DLG_H
