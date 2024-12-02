/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef PRI_KEY_INFO_DLG_H
#define PRI_KEY_INFO_DLG_H

#include "js_bin.h"
#include <QDialog>
#include "ui_pri_key_info_dlg.h"
#include "js_pkcs11.h"

namespace Ui {
class PriKeyInfoDlg;
}

class PriKeyInfoDlg : public QDialog, public Ui::PriKeyInfoDlg
{
    Q_OBJECT

public:
    explicit PriKeyInfoDlg(QWidget *parent = nullptr);
    ~PriKeyInfoDlg();

    void setPrivateKey( const BIN *pPriKey );
    void setPublicKey( const BIN *pPubKey );

    void setPrivateKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey );
    void setPublicKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey );

    void readPrivateKey( BIN *pPriKey );
    void readPublicKey( BIN *pPubKey );

private slots:
    void showEvent(QShowEvent *event);

    void changeRSA_N();
    void changeRSA_E( const QString& text );
    void changeRSA_D();
    void changeRSA_P( const QString& text );
    void changeRSA_Q( const QString& text );
    void changeRSA_DMP1( const QString& text );
    void changeRSA_DMQ1( const QString& text );
    void changeRSA_IQMP( const QString& text );

    void changeECC_PubX();
    void changeECC_PubY();
    void changeECC_Private();

    void changeDSA_G();
    void changeDSA_P();
    void changeDSA_Q( const QString& text );
    void changeDSA_Public();
    void changeDSA_Private( const QString& text );

    void changeEdDSA_RawPublic();
    void changeEdDSA_RawPrivate();

    void clearAll();
    void clickCheckPubKey();


private:
    void initialize();
    bool isChanged();

    void setRSAKey( const BIN *pKey, bool bPri = true );
    void setECCKey( const BIN *pKey, bool bPri = true );
    void setDSAKey( const BIN *pKey, bool bPri = true );
    void setEdDSAKey( int nKeyType, const BIN *pKey, bool bPri = true );

    void setRSAKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, bool bPri = true );
    void setECCKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, bool bPri = true );
    void setDSAKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, bool bPri = true );
    void setEdDSAKey( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, bool bPri = true );

    void setModeUI( bool bVal );

    BIN pri_key_;
    BIN pub_key_;
    int key_type_;

    CK_SESSION_HANDLE session_;
    CK_OBJECT_HANDLE pri_handle_;
    CK_OBJECT_HANDLE pub_handle_;
};

#endif // PRI_KEY_INFO_DLG_H
