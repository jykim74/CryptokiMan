#ifndef GEN_KEY_PAIR_DLG_H
#define GEN_KEY_PAIR_DLG_H

#include <QDialog>
#include "ui_gen_key_pair_dlg.h"

namespace Ui {
class GenKeyPairDlg;
}

class GenKeyPairDlg : public QDialog, public Ui::GenKeyPairDlg
{
    Q_OBJECT

public:
    explicit GenKeyPairDlg(QWidget *parent = nullptr);
    ~GenKeyPairDlg();
    void setSelectedSlot( int index );

private slots:
    virtual void accept();
    void slotChanged( int index );
    void mechChanged( int nIndex );

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

private:
    void initialize();
    void initAttributes();
    void setAttributes();
    void connectAttributes();
    void setDefaults();
};

#endif // GEN_KEY_PAIR_DLG_H
