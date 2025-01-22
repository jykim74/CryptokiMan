#ifndef CAVP_DLG_H
#define CAVP_DLG_H

#include <QDialog>
#include "ui_cavp_dlg.h"
#include "js_bin.h"

namespace Ui {
class CAVPDlg;
}

class CAVPDlg : public QDialog, public Ui::CAVPDlg
{
    Q_OBJECT

public:
    explicit CAVPDlg(QWidget *parent = nullptr);
    ~CAVPDlg();

    void setSelectedSlot( int index );

private slots:
    void slotChanged( int index );
    void clickFindRsp();
    void clickMCT_SymClear();
    void clickMCT_HashClear();
    void clickMCT_SymRun();
    void clickMCT_HashRun();

private:
    void initUI();
    void initialize();
    void logRsp( const QString strLog );

    int makeSym_MCT( const QString strAlgMode, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymDec_MCT( const QString strAlgMode, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin = false );

    int makeSymECB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pPT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymCBC_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymCTR_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymCFB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymOFB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pPT, QJsonArray& jsonRes, bool bWin = false );

    /* Need to support decrypt */
    int makeSymDecECB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pCT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymDecCBC_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymDecCTR_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymDecCFB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin = false );
    int makeSymDecOFB_MCT( int nKeyAlg, const BIN *pKey, const BIN *pIV, const BIN *pCT, QJsonArray& jsonRes, bool bWin = false );

    int makeHash_MCT( const QString strAlg, const BIN *pSeed, QJsonArray& jsonRes, bool bWin = false );
    int makeHash_AlternateMCT( const QString strAlg, const BIN *pSeed, QJsonArray& jsonRes, bool bWin = false );

    int createKey( int nKeyType, const BIN *pKey, long *phObj );
    int genKeyPair( int nGenKeyType, long *phPri, long *phPub );

    long session_;
    int slot_index_;
};

#endif // CAVP_DLG_H
