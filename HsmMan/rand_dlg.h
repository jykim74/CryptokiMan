#ifndef RAND_DLG_H
#define RAND_DLG_H

#include <QDialog>

namespace Ui {
class RandDlg;
}

class RandDlg : public QDialog
{
    Q_OBJECT

public:
    explicit RandDlg(QWidget *parent = nullptr);
    ~RandDlg();

private:
    Ui::RandDlg *ui;
};

#endif // RAND_DLG_H
