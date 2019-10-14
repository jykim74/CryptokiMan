#ifndef GEN_RSA_PRI_KEY_DLG_H
#define GEN_RSA_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_gen_rsa_pri_key_dlg.h"

namespace Ui {
class GenRSAPriKeyDlg;
}

class GenRSAPriKeyDlg : public QDialog, public Ui::GenRSAPriKeyDlg
{
    Q_OBJECT

public:
    explicit GenRSAPriKeyDlg(QWidget *parent = nullptr);
    ~GenRSAPriKeyDlg();

private:

};

#endif // GEN_RSA_PRI_KEY_DLG_H
