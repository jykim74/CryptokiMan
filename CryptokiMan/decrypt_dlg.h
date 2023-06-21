#ifndef DECRYPT_DLG_H
#define DECRYPT_DLG_H

#include <QDialog>
#include "ui_decrypt_dlg.h"

namespace Ui {
class DecryptDlg;
}

class DecryptDlg : public QDialog, public Ui::DecryptDlg
{
    Q_OBJECT

public:
    explicit DecryptDlg(QWidget *parent = nullptr);
    ~DecryptDlg();
    void setSelectedSlot( int index );
    void setObject( int type, long hObj );
    void changeType( int type );

private slots:
    void slotChanged( int index );

    int clickInit();
    void clickUpdate();
    void clickFinal();

    void clickDecrypt();
    void runDataDecrypt();
    void runFileDecrypt();
    void clickClose();

    void keyTypeChanged( int index );
    void labelChanged( int index );

    void inputChanged();
    void outputChanged();
    void paramChanged();

    void clickInputClear();
    void clickOutputClear();

    void clickFindSrcFile();
    void clickFindDstFile();

private:
    void initialize();
    void initUI();

    int slot_index_ = -1;
    long session_ = -1;

};

#endif // DECRYPT_DLG_H
