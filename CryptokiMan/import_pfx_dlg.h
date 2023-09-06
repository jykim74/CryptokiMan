#ifndef IMPORT_PFX_DLG_H
#define IMPORT_PFX_DLG_H

#include <QDialog>
#include "ui_import_pfx_dlg.h"
#include "js_pki.h"
#include "js_pki_eddsa.h"

namespace Ui {
class ImportPFXDlg;
}

class ImportPFXDlg : public QDialog, public Ui::ImportPFXDlg
{
    Q_OBJECT

public:
    explicit ImportPFXDlg(QWidget *parent = nullptr);
    ~ImportPFXDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );

    void clickCertUseSKI();
    void clickCertPrivate();
    void clickCertSensitive();
    void clickCertModifiable();
    void clickCertToken();
    void clickCertStartDate();
    void clickCertEndDate();

    void clickPriUseSKI();
    void clickPriPrivate();
    void clickPriDecrypt();
    void clickPriSign();
    void clickPriSignRecover();
    void clickPriUnwrap();
    void clickPriModifiable();
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
    void clickPubToken();
    void clickPubStartDate();
    void clickPubEndDate();

    void clickFind();

    void clickCertSubjectInCertCheck();
    void clickPriSubjectInCertCheck();

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
    int createDSAPublicKey( JDSAKeyVal *pDSAKeyVal );
    int createDSAPrivateKey( JDSAKeyVal *pDSAKeyVal );

    void setDefaults();

    BIN der_dn_;
    BIN ski_;
};

#endif // IMPORT_PFX_DLG_H
