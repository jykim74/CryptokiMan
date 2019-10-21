#ifndef INIT_TOKEN_DLG_H
#define INIT_TOKEN_DLG_H

#include <QDialog>
#include "ui_init_token_dlg.h"

namespace Ui {
class InitTokenDlg;
}

class InitTokenDlg : public QDialog, public Ui::InitTokenDlg
{
    Q_OBJECT

public:
    explicit InitTokenDlg(QWidget *parent = nullptr);
    ~InitTokenDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void slotChanged( int index );

private:
    void initialize();
};

#endif // INIT_TOKEN_DLG_H
