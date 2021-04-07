#ifndef RAND_DLG_H
#define RAND_DLG_H

#include <QDialog>
#include "ui_rand_dlg.h"

namespace Ui {
class RandDlg;
}

class RandDlg : public QDialog, public Ui::RandDlg
{
    Q_OBJECT

public:
    explicit RandDlg(QWidget *parent = nullptr);
    ~RandDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );
    void clickSeed();

private:
    void initialize();
    void initUI();
};

#endif // RAND_DLG_H
