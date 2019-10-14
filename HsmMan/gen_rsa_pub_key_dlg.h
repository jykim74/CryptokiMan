#ifndef GEN_RSA_PUB_KEY_DLG_H
#define GEN_RSA_PUB_KEY_DLG_H

#include <QDialog>
#include "ui_gen_rsa_pub_key_dlg.h"

namespace Ui {
class GenRSAPubKeyDlg;
}

class GenRSAPubKeyDlg : public QDialog, public Ui::GenRSAPubKeyDlg
{
    Q_OBJECT

public:
    explicit GenRSAPubKeyDlg(QWidget *parent = nullptr);
    ~GenRSAPubKeyDlg();

private:

};

#endif // GEN_RSA_PUB_KEY_DLG_H
