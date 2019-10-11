#ifndef GEN_DATA_DLG_H
#define GEN_DATA_DLG_H

#include <QDialog>
#include "ui_gen_data_dlg.h"

namespace Ui {
class GenDataDlg;
}

class GenDataDlg : public QDialog, public Ui::GenDataDlg
{
    Q_OBJECT

public:
    explicit GenDataDlg(QWidget *parent = nullptr);
    ~GenDataDlg();

private:

};

#endif // GEN_DATA_DLG_H
