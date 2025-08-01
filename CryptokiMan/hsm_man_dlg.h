#ifndef HSM_MAN_DLG_H
#define HSM_MAN_DLG_H

#include <QDialog>
#include "slot_info.h"
#include "ui_hsm_man_dlg.h"
#include "js_pkcs11.h"

enum {
    HsmModeManage = 0,
    HsmModeSelectCert,
    HsmModeSelectPublicKey,
    HsmModeSelectPrivateKey,
    HsmModeSelectSecretKey,
    HsmModeSelectDeriveKey
};

enum {
    HsmUsageAny = 0,
    HsmUsageSign,
    HsmUsageVerify,
    HsmUsageEncrypt,
    HsmUsageDecrypt,
    HsmUsageWrap,
    HsmUsageUnwrap,
    HsmUsageDerive
};

enum {
    TAB_CERT_IDX = 0,
    TAB_PUBLIC_IDX = 1,
    TAB_PRIVATE_IDX = 2,
    TAB_SECRET_IDX = 3
};

namespace Ui {
class HsmManDlg;
}

class HsmManDlg : public QDialog, public Ui::HsmManDlg
{
    Q_OBJECT

public:
    explicit HsmManDlg(QWidget *parent = nullptr);
    ~HsmManDlg();

    void setSlotIndex( int index );
    int getSlotIndex() { return slot_index_; };

    void setMode( int nMode, int nUsage = HsmUsageAny );
    void setTitle( const QString strTitle );
    const QString getData() { return str_data_; };
    void setTabIdx( int nIdx );

private slots:
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *event );

    void slotCertTableMenuRequested( QPoint pos );
    void slotPubKeyTableMenuRequested( QPoint pos );
    void slotPriKeyTableMenuRequested( QPoint pos );
    void slotSecretTableMenuRequested( QPoint pos );

    void changeTab(int index);
    void changeUsage();

    void loadCertList();
    void loadPublicList();
    void loadPrivateList();
    void loadSecretList();

    void clickCertObjectView();
    void clickCertView();
    void clickCertDelete();
    void clickCertExport();
    void clickCertDeleteKeyPair();

    void clickPublicObjectView();
    void clickPublicView();
    void clickPublicDelete();
    void clickPublicExport();
    void clickPublicVerify();
    void clickPublicEncrypt();

    void clickPrivateObjectView();
    void clickPrivateView();
    void clickPrivateDelete();
    void clickPrivateExport();
    void clickPrivateSign();
    void clickPrivateDecrypt();

    void clickSecretObjectView();
    void clickSecretView();
    void clickSecretDelete();
    void clickSecretEncrypt();
    void clickSecretDecrypt();
    void clickSecretSign();
    void clickSecretVerify();

    void clickOK();

private:
    void initUI();
    void initialize();
    void setUsageTemplate( CK_ATTRIBUTE sTemplate[], long& uCount );

    SlotInfo slot_info_;
    int slot_index_ = -1;

    QString str_data_;
};

#endif // HSM_MAN_DLG_H
