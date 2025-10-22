/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef IMPORT_CERT_DLG_H
#define IMPORT_CERT_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_import_cert_dlg.h"

namespace Ui {
class ImportCertDlg;
}

class ImportCertDlg : public QDialog, public Ui::ImportCertDlg
{
    Q_OBJECT

public:
    explicit ImportCertDlg(QWidget *parent = nullptr);
    ~ImportCertDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    virtual void accept();
    void clickUseSKI();
    void clickUseSPKI();

    void clickPrivate();
    void clickModifiable();
    void clickCopyable();
    void clickDestroyable();
    void clickToken();
    void clickTrusted();
    void clickStartDate();
    void clickEndDate();

    void clickFind();
    void clickSubjectInCertCheck();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // IMPORT_CERT_DLG_H
