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

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void slotChanged( int index );

    void clickPrivate();
    void clickSensitive();
    void clickModifiable();
    void clickToken();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
};

#endif // GEN_DATA_DLG_H
