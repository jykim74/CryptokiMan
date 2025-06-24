/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef COPY_OBJECT_DLG_H
#define COPY_OBJECT_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_copy_object_dlg.h"
#include "js_pkcs11.h"

namespace Ui {
class CopyObjectDlg;
}

class CopyObjectDlg : public QDialog, public Ui::CopyObjectDlg
{
    Q_OBJECT

public:
    explicit CopyObjectDlg(QWidget *parent = nullptr);
    ~CopyObjectDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

    void setTypeObject( int nType, const QString strLabel, long hObj );

private slots:
    virtual void accept();
    void clickObjectView();

    void changeSrcType( int index );
    void changeSrcLabel( int index );

    void clickPrivate();
    void clickModifiable();
    void clickDestroyable();
    void clickToken();

private:
    void initUI();
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();

    void readSrcLabels( CK_OBJECT_CLASS objClass );

    void readSrcSecretKeyLabels();
    void readSrcPrivateKeyLabels();
    void readSrcPublicKeyLabels();
    void readSrcCertificateLabels();
    void readSrcDataLabels();

    SlotInfo slot_info_;
    int slot_index_ = -1;

    bool is_fix_;
};

#endif // COPY_OBJECT_DLG_H
