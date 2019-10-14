#ifndef DIGEST_DLG_H
#define DIGEST_DLG_H

#include <QDialog>
#include "ui_digest_dlg.h"

namespace Ui {
class DigestDlg;
}

class DigestDlg : public QDialog, public Ui::DigestDlg
{
    Q_OBJECT

public:
    explicit DigestDlg(QWidget *parent = nullptr);
    ~DigestDlg();

private:

};

#endif // DIGEST_DLG_H
