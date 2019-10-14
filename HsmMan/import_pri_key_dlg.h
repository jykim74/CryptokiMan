#ifndef IMPORT_PRI_KEY_DLG_H
#define IMPORT_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_import_pri_key_dlg.h"

namespace Ui {
class ImportPriKeyDlg;
}

class ImportPriKeyDlg : public QDialog, public Ui::ImportPriKeyDlg
{
    Q_OBJECT

public:
    explicit ImportPriKeyDlg(QWidget *parent = nullptr);
    ~ImportPriKeyDlg();

private:

};

#endif // IMPORT_PRI_KEY_DLG_H
