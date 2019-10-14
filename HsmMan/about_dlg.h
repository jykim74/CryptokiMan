#ifndef ABOUT_DLG_H
#define ABOUT_DLG_H

#include <QDialog>
#include "ui_about_dlg.h"

namespace Ui {
class AboutDlg;
}

class AboutDlg : public QDialog, public Ui::AboutDlg
{
    Q_OBJECT

public:
    explicit AboutDlg(QWidget *parent = nullptr);
    ~AboutDlg();

private:

};

#endif // ABOUT_DLG_H
