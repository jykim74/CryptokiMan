#ifndef GEN_KEY_PAIR_DLG_H
#define GEN_KEY_PAIR_DLG_H

#include <QDialog>
#include "ui_gen_key_pair_dlg.h"

namespace Ui {
class GenKeyPairDlg;
}

class GenKeyPairDlg : public QDialog, public Ui::GenKeyPairDlg
{
    Q_OBJECT

public:
    explicit GenKeyPairDlg(QWidget *parent = nullptr);
    ~GenKeyPairDlg();

private:

};

#endif // GEN_KEY_PAIR_DLG_H
