#ifndef GEN_KEY_DLG_H
#define GEN_KEY_DLG_H

#include <QDialog>
#include "ui_gen_key_dlg.h"

namespace Ui {
class GenKeyDlg;
}

class GenKeyDlg : public QDialog, public Ui::GenKeyDlg
{
    Q_OBJECT

public:
    explicit GenKeyDlg(QWidget *parent = nullptr);
    ~GenKeyDlg();

private:

};

#endif // GEN_KEY_DLG_H
