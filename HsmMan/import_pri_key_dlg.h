#ifndef IMPORT_PRI_KEY_DLG_H
#define IMPORT_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_import_pri_key_dlg.h"
#include "js_pki.h"

namespace Ui {
class ImportPriKeyDlg;
}

class ImportPriKeyDlg : public QDialog, public Ui::ImportPriKeyDlg
{
    Q_OBJECT

public:
    explicit ImportPriKeyDlg(QWidget *parent = nullptr);
    ~ImportPriKeyDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void slotChanged( int index );

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

    int createRSAPublicKey( JSRSAKeyVal *pRsaKeyVal );
    int createRSAPrivateKey( JSRSAKeyVal *pRsaKeyVal );
    int createECPublicKey( JSECKeyVal *pEcKeyVal );
    int createECPrivateKey( JSECKeyVal *pECKeyVal );

    void setDefaults();
};

#endif // IMPORT_PRI_KEY_DLG_H
