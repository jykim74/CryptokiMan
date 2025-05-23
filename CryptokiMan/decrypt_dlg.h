/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef DECRYPT_DLG_H
#define DECRYPT_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_decrypt_dlg.h"

class DecryptThread;

namespace Ui {
class DecryptDlg;
}

class DecryptDlg : public QDialog, public Ui::DecryptDlg
{
    Q_OBJECT

public:
    explicit DecryptDlg(QWidget *parent = nullptr);
    ~DecryptDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

    void setObject( int type, long hObj );
    void changeType( int type );

private slots:
    void mechChanged( int index );

    int clickInit();
    void clickUpdate();
    int clickFinal();

    void clickDecrypt();
    void runDataDecrypt();
    void runFileDecrypt();
    void clickClose();

    void clickSelect();

    void keyTypeChanged( int index );

    void inputChanged();
    void outputChanged();
    void paramChanged();
    void aadChanged();
    void oaepSourceChanged();

    void clickInputClear();
    void clickOutputClear();

    void clickFindSrcFile();
    void clickFindDstFile();

    void runFileDecryptThread();
    void startTask();
    void onTaskFinished();
    void onTaskUpdate( int nUpdate );
private:
    void initialize();
    void clearStatusLabel();
    void setStatusInit( int rv );
    void setStatusUpdate( int rv, int count );
    void setStatusFinal( int rv );
    void setStatusDecrypt( int rv );

    void initUI();
    void setMechanism( void *pMech );
    void freeMechanism( void *pMech );

    SlotInfo slot_info_;
    int slot_index_ = -1;

    DecryptThread* thread_;
    int update_cnt_;
    int status_type_ = -1;
};

#endif // DECRYPT_DLG_H
