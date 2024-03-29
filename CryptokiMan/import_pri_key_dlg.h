/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef IMPORT_PRI_KEY_DLG_H
#define IMPORT_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_import_pri_key_dlg.h"
#include "js_pki.h"
#include "js_pki_eddsa.h"

namespace Ui {
class ImportPriKeyDlg;
}

class ImportPriKeyDlg : public QDialog, public Ui::ImportPriKeyDlg
{
    Q_OBJECT

public:
    explicit ImportPriKeyDlg(QWidget *parent = nullptr);
    ~ImportPriKeyDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void checkPubImport();
    void checkEncPriKey();

    void clickPriUseSKI();
    void clickPriUseSPKI();

    void clickPriPrivate();
    void clickPriDecrypt();
    void clickPriSign();
    void clickPriSignRecover();
    void clickPriUnwrap();
    void clickPriModifiable();
    void clickPriCopyable();
    void clickPriDestroyable();
    void clickPriSensitive();
    void clickPriDerive();
    void clickPriExtractable();
    void clickPriToken();
    void clickPriStartDate();
    void clickPriEndDate();

    void clickPubUseSKI();
    void clickPubPrivate();
    void clickPubEncrypt();
    void clickPubWrap();
    void clickPubVerify();
    void clickPubVerifyRecover();
    void clickPubDerive();
    void clickPubModifiable();
    void clickPubCopyable();
    void clickPubDestroyable();
    void clickPubToken();
    void clickPubTrusted();
    void clickPubStartDate();
    void clickPubEndDate();

    void clickFind();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    int readPrivateKey( BIN *pPriKey );

    int createRSAPublicKey( JRSAKeyVal *pRsaKeyVal );
    int createRSAPrivateKey( JRSAKeyVal *pRsaKeyVal );
    int createECPublicKey( JECKeyVal *pEcKeyVal );
    int createECPrivateKey( JECKeyVal *pECKeyVal );
    int createDSAPublicKey( JDSAKeyVal *pDSAKeyVal );
    int createDSAPrivateKey( JDSAKeyVal *pDSAKeyVal );

    void setDefaults();

    BIN ski_;
    BIN spki_;
};

#endif // IMPORT_PRI_KEY_DLG_H
