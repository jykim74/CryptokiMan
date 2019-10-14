#ifndef GEN_EC_PRI_KEY_DLG_H
#define GEN_EC_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_gen_ec_pri_key_dlg.h"

namespace Ui {
class GenECPriKeyDlg;
}

class GenECPriKeyDlg : public QDialog, public Ui::GenECPriKeyDlg
{
    Q_OBJECT

public:
    explicit GenECPriKeyDlg(QWidget *parent = nullptr);
    ~GenECPriKeyDlg();

private:

};

#endif // GEN_EC_PRI_KEY_DLG_H
