/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef COPY_OBJECT_DLG_H
#define COPY_OBJECT_DLG_H

#include <QDialog>
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

    void setSelectedSlot( int index );
    void setTypeObject( int nType, const QString strLabel, long hObj );

private slots:
    virtual void accept();
    void slotChanged( int index );

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

    int slot_index_;
    long session_;
    bool is_fix_;
};

#endif // COPY_OBJECT_DLG_H
