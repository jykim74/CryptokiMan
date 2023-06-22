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
    void setSelectedSlot( int index );
    void changeType( int type );
    void setObject( int type, long hObj );

private slots:
    void slotChanged( int index );

    int clickInit();
    void clickUpdate();
    void clickFinal();
    void clickVerify();
    void runDataVerify();
    void runFileVerify();
    void clickClose();

    void clickVerifyRecoverInit();
    void clickVerifyRecover();

    void keyTypeChanged( int index );
    void labelChanged( int index );

    void changeInput();
    void changeSign();

    void clickInputClear();
    void clickSignClear();
    void clickFindSrcFile();

private:
    void initialize();
    void appendStatusLabel( const QString& strLabel );
    void initUI();

    int slot_index_;
    long session_;
};

#endif // VERIFY_DLG_H
