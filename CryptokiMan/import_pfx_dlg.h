/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef IMPORT_PFX_DLG_H
#define IMPORT_PFX_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_import_pfx_dlg.h"
#include "js_pki.h"
#include "js_pki_raw.h"
#include "pkcs11.h"

namespace Ui {
class ImportPFXDlg;
}

class ImportPFXDlg : public QDialog, public Ui::ImportPFXDlg
{
    Q_OBJECT

public:
    explicit ImportPFXDlg(QWidget *parent = nullptr);
    ~ImportPFXDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

private slots:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    virtual void accept();

    void clickPriSameLabel();
    void clickPubSameLabel();
    void clickCertSameLabel();

    void clickCertUseSKI();
    void clickCertUseSPKI();

    void clickCertPrivate();
    void clickCertModifiable();
    void clickCertCopyable();
    void clickCertDestroyable();
    void clickCertToken();
    void clickCertTrusted();
    void clickCertStartDate();
    void clickCertEndDate();

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

    void clickCertSubjectInCertCheck();
    void clickPriSubjectInCertCheck();
    void clickPubSubjectInCertCheck();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    int createCert( BIN *pCert );
    int createRSAPublicKey( JRSAKeyVal *pRsaKeyVal );
    int createRSAPrivateKey( JRSAKeyVal *pRsaKeyVal );
    int createECPublicKey( JECKeyVal *pEcKeyVal );
    int createECPrivateKey( JECKeyVal *pECKeyVal );
    int createEDPublicKey( JRawKeyVal *pRawKeyVal );
    int createEDPrivateKey( JRawKeyVal *pRawKeyVal );
    int createDSAPublicKey( JDSAKeyVal *pDSAKeyVal );
    int createDSAPrivateKey( JDSAKeyVal *pDSAKeyVal );

    void setPubBoolTemplate( CK_ATTRIBUTE sTemplate[], CK_ULONG& uCount );
    void setPriBoolTemplate( CK_ATTRIBUTE sTemplate[], CK_ULONG& uCount );

    void setDefaults();

    BIN der_dn_;
    BIN ski_;
    BIN spki_;

    SlotInfo slot_info_;
    int slot_index_ = -1;
};

#endif // IMPORT_PFX_DLG_H
