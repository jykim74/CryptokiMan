#ifndef GEN_EC_PUB_KEY_DLG_H
#define GEN_EC_PUB_KEY_DLG_H

#include <QDialog>
#include "ui_gen_ec_pub_key_dlg.h"

namespace Ui {
class GenECPubKeyDlg;
}

class GenECPubKeyDlg : public QDialog, public Ui::GenECPubKeyDlg
{
    Q_OBJECT

public:
    explicit GenECPubKeyDlg(QWidget *parent = nullptr);
    ~GenECPubKeyDlg();

private:

};

#endif // GEN_EC_PUB_KEY_DLG_H
