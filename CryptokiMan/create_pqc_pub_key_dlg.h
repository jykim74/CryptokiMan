#ifndef CREATE_PQC_PUB_KEY_DLG_H
#define CREATE_PQC_PUB_KEY_DLG_H

#include <QDialog>
#include "ui_create_pqc_pub_key_dlg.h"

namespace Ui {
class CreatePQCPubKeyDlg;
}

class CreatePQCPubKeyDlg : public QDialog, public Ui::CreatePQCPubKeyDlg
{
    Q_OBJECT

public:
    explicit CreatePQCPubKeyDlg(QWidget *parent = nullptr);
    ~CreatePQCPubKeyDlg();

private:

};

#endif // CREATE_PQC_PUB_KEY_DLG_H
