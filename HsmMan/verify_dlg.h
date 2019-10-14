#ifndef VERIFY_DLG_H
#define VERIFY_DLG_H

#include <QDialog>
#include "ui_verify_dlg.h"

namespace Ui {
class VerifyDlg;
}

class VerifyDlg : public QDialog, public Ui::VerifyDlg
{
    Q_OBJECT

public:
    explicit VerifyDlg(QWidget *parent = nullptr);
    ~VerifyDlg();

private:

};

#endif // VERIFY_DLG_H
