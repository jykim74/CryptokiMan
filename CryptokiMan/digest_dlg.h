/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef DIGEST_DLG_H
#define DIGEST_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_digest_dlg.h"

class DigestThread;

namespace Ui {
class DigestDlg;
}

class DigestDlg : public QDialog, public Ui::DigestDlg
{
    Q_OBJECT

public:
    explicit DigestDlg(QWidget *parent = nullptr);
    ~DigestDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    void changeMech( int index );

    void changeParam( const QString text );

    void clickSelectKey();
    void clickDigestKey();
    int clickInit();
    void clickUpdate();
    void clickFinal();
    void clickDigest();
    void runDataDigest();
    void runFileDigest();
    void clickClose();

    void inputChanged();
    void outputChanged();

    void clickInputClear();
    void clickOutputClear();
    void clickFindSrcFile();

    void runFileDigestThread();
    void startTask();
    void onTaskFinished();
    void onTaskUpdate( qint64 nUpdate );

private:
    void initialize();
    void clearStatusLabel();
    void setStatusInit( int rv );
    void setStatusUpdate( int rv, int count );
    void setStatusFinal( int rv );
    void setStatusDigest( int rv );

    void initUI();

    long getSessionHandle();

    DigestThread* thread_;
    int update_cnt_;

    SlotInfo slot_info_;
    int slot_index_ = -1;

    int status_type_ = -1;
};

#endif // DIGEST_DLG_H
