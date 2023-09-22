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

    int clickInit();
    void clickUpdate();
    void clickFinal();
    void clickSign();
    void runDataSign();
    void runFileSign();
    void clickClose();

    void clickSignRecoverInit();
    void clickSignRecover();

    void labelChanged( int index );
    void keyTypeChanged( int index );

    void changeInput();
    void changeOutput();
    void changeParam( const QString text );

    void clickInputClear();
    void clickOutputClear();
    void clickFindSrcFile();

private:
    void initialize();
    void appendStatusLabel( const QString& strLabel );
    void initUI();

    long session_;
    int slot_index_;
};

#endif // SIGN_DLG_H
