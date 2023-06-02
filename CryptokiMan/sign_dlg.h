#ifndef SIGN_DLG_H
#define SIGN_DLG_H

#include <QDialog>
#include "ui_sign_dlg.h"

namespace Ui {
class SignDlg;
}

class SignDlg : public QDialog, public Ui::SignDlg
{
    Q_OBJECT

public:
    explicit SignDlg(QWidget *parent = nullptr);
    ~SignDlg();
    void setSelectedSlot( int index );
    void setObject( int type, long hObj );
    void changeType( int type );

private slots:
    void slotChanged( int index );

    void clickInit();
    void clickUpdate();
    void clickFinal();
    void clickSign();
    void clickClose();

    void clickSignRecoverInit();
    void clickSignRecover();

    void labelChanged( int index );
    void keyTypeChanged( int index );

    void changeInput();
    void changeOutput();

private:
    void initialize();
    void initUI();

    long session_;
    int slot_index_;
};

#endif // SIGN_DLG_H
