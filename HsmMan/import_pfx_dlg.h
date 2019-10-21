#ifndef IMPORT_PFX_DLG_H
#define IMPORT_PFX_DLG_H

#include <QDialog>
#include "ui_import_pfx_dlg.h"
#include "js_pki.h"

namespace Ui {
class ImportPFXDlg;
}

class ImportPFXDlg : public QDialog, public Ui::ImportPFXDlg
{
    Q_OBJECT

public:
    explicit ImportPFXDlg(QWidget *parent = nullptr);
    ~ImportPFXDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void slotChanged( int index );

    void clickCertPrivate();
    void clickCertSensitive();
    void clickCertModifiable();
    void clickCertToken();

    void clickPriPrivate();
    void clickPriDecrypt();
    void clickPriSign();
    void clickPriUnwrap();
    void clickPriModifiable();
    void clickPriSensitive();
    void clickPriDerive();
    void clickPriExtractable();
    void clickPriToken();

    void clickPubPrivate();
    void clickPubEncrypt();
    void clickPubWrap();
    void clickPubVerify();
    void clickPubDerive();
    void clickPubModifiable();
    void clickPubToken();

    void clickFind();

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();

    int createCert( BIN *pCert );
    int createRSAPublicKey( JSRSAKeyVal *pRsaKeyVal );
    int createRSAPrivateKey( JSRSAKeyVal *pRsaKeyVal );
    int createECPublicKey( JSECKeyVal *pEcKeyVal );
    int createECPrivateKey( JSECKeyVal *pECKeyVal );
};

#endif // IMPORT_PFX_DLG_H
