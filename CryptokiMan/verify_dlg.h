/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef VERIFY_DLG_H
#define VERIFY_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_verify_dlg.h"

class VerifyThread;

namespace Ui {
class VerifyDlg;
}

class VerifyDlg : public QDialog, public Ui::VerifyDlg
{
    Q_OBJECT

public:
    explicit VerifyDlg(QWidget *parent = nullptr);
    ~VerifyDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

    void changeType( int type );
    void setObject( int type, long hObj );

private slots:
    int clickInit();
    void clickUpdate();
    void clickFinal();
    void clickVerify();
    void runDataVerify();
    void runFileVerify();
    void clickClose();

    void clickSelect();
    void clickObjectView();

    void clickVerifyRecoverInit();
    void clickVerifyRecover();

    void keyTypeChanged( int index );
    void changeParam(const QString text );
    void mechChanged( int index );

    void changeInput();
    void changeSign();

    void clickInputClear();
    void clickSignClear();
    void clickFindSrcFile();

    void runFileVerifyThread();
    void startTask();
    void onTaskFinished();
    void onTaskUpdate( qint64 nUpdate );
private:
    void initialize();

    void clearStatusLabel();
    void setStatusInit( int rv );
    void setStatusUpdate( int rv, int count );
    void setStatusFinal( int rv );
    void setStatusVerify( int rv );

    void initUI();

    SlotInfo slot_info_;
    int slot_index_ = -1;

    VerifyThread* thread_;
    int update_cnt_;
    int status_type_ = -1;
};

#endif // VERIFY_DLG_H
