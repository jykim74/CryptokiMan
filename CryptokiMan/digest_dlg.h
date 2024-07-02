/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef DIGEST_DLG_H
#define DIGEST_DLG_H

#include <QDialog>
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
    void setSelectedSlot( int index );

private slots:
    void slotChanged( int index );
    void changeKeyLabel( int index );

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
    void onTaskUpdate( int nUpdate );

private:
    void initialize();
    void appendStatusLabel( const QString& strLabel );
    void initUI();
    void setKeyList();

    long getSessionHandle();

    DigestThread* thread_;
    int update_cnt_;
};

#endif // DIGEST_DLG_H
