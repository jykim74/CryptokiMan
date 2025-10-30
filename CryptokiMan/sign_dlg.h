/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SIGN_DLG_H
#define SIGN_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_sign_dlg.h"

class SignThread;

namespace Ui {
class SignDlg;
}

class SignDlg : public QDialog, public Ui::SignDlg
{
    Q_OBJECT

public:
    explicit SignDlg(QWidget *parent = nullptr);
    ~SignDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

    void setObject( int type, long hObj );
    void changeType( int type );

private slots:
    int clickInit();
    void clickUpdate();
    void clickFinal();
    void clickSign();
    void runDataSign();
    void runFileSign();
    void clickClose();

    void clickSelect();
    void clickObjectView();

    void clickSignRecoverInit();
    void clickSignRecover();

    void keyTypeChanged( int index );
    void mechChanged( int index );

    void changeInput();
    void changeOutput();
    void changeParam( const QString text );

    void clickInputClear();
    void clickOutputClear();
    void clickFindSrcFile();

    void runFileSignThread();
    void startTask();
    void onTaskFinished();
    void onTaskUpdate( qint64 nUpdate );

private:
    void initUI();
    void initialize();

    void clearStatusLabel();
    void setStatusInit( int rv );
    void setStatusUpdate( int rv, int count );
    void setStatusFinal( int rv );
    void setStatusSign( int rv );

    SlotInfo slot_info_;
    int slot_index_ = -1;

    SignThread* thread_;
    int update_cnt_;
    int status_type_ = -1;
};

#endif // SIGN_DLG_H
