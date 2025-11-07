/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef ENCRYPT_DLG_H
#define ENCRYPT_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_encrypt_dlg.h"

class EncryptThread;

namespace Ui {
class EncryptDlg;
}

class EncryptDlg : public QDialog, public Ui::EncryptDlg
{
    Q_OBJECT

public:
    explicit EncryptDlg(QWidget *parent = nullptr);
    ~EncryptDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

    void setObject( int type, long hObj );
    void changeType( int type );

private slots:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);
    void mechChanged( int index );

    void clickReset();

    int clickInit();
    void clickUpdate();
    int clickFinal();
    void clickEncrypt();
    void runDataEncrypt();
    void runFileEncrypt();
    void clickClose();

    void clickSelect();
    void clickObjectView();

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

    void runFileEncryptThread();
    void startTask();
    void onTaskFinished();
    void onTaskUpdate( qint64 nUpdate );

private:
    void initUI();
    void initialize();
    void setSrcFileInfo( const QString strFile );

    void clearStatusLabel();
    void setStatusInit( int rv );
    void setStatusUpdate( int rv, int count );
    void setStatusFinal( int rv );
    void setStatusEncrypt( int rv );

    void setMechanism( void *pMech );
    void freeMechanism( void *pMech );

    SlotInfo slot_info_;
    int slot_index_ = -1;

    EncryptThread* thread_;
    int update_cnt_;
    int status_type_ = -1;
};

#endif // ENCRYPT_DLG_H
