#ifndef ENCRYPT_DLG_H
#define ENCRYPT_DLG_H

#include <QDialog>
#include "ui_encrypt_dlg.h"

namespace Ui {
class EncryptDlg;
}

class EncryptDlg : public QDialog, public Ui::EncryptDlg
{
    Q_OBJECT

public:
    explicit EncryptDlg(QWidget *parent = nullptr);
    ~EncryptDlg();
    void setSelectedSlot( int index );
    void setObject( int type, long hObj );
    void changeType( int type );

private slots:
    void slotChanged( int index );
    void mechChanged( int index );

    int clickInit();
    void clickUpdate();
    void clickFinal();
    void clickEncrypt();
    void runDataEncrypt();
    void runFileEncrypt();
    void clickClose();

    void keyTypeChanged( int index );
    void labelChanged( int index );

    void inputChanged();
    void outputChanged();
    void paramChanged();
    void aadChanged();

    void clickInputClear();
    void clickOutputClear();

    void clickFindSrcFile();
    void clickFindDstFile();

private:
    void initialize();
    void appendStatusLabel( const QString& strLabel );
    void initUI();
    void setMechanism( void *pMech );
    void freeMechanism( void *pMech );

    int slot_index_;
    long session_;
};

#endif // ENCRYPT_DLG_H
