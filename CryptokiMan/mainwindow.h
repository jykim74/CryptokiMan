/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSplitter>
#include <QTreeView>
#include <QTableWidget>
#include <QTextEdit>
#include "js_pkcs11.h"
#include "temp_array.h"
#include "slot_info.h"
#include "common.h"
#include "code_editor.h"

class ManTreeView;
class ManTreeModel;
class ManTreeItem;
class ThreadWork;

class HsmManDlg;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void initialize();
    void showWindow();

    void infoClear();

    QList<SlotInfo>& getSlotInfos() { return slot_infos_; };
    ManTreeItem* currentTreeItem();
    ManTreeItem* getRootItem();

    void info( QString strInfo, QColor cr = QColor(0x00, 0x00, 0x00) );
    void info_w( QString strInfo );

    void infoLine();
    void infoLine2();

    void log( const QString strLog );
    void elog( const QString strLog );
    void wlog( const QString strLog );
    void dlog( const QString strLog );
    void write( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );

    void showTypeList( int nSlotIndex, int nType );

    void showGetInfoList();
    void showSlotInfoList( int index );
    void showTokenInfoList( int index );
    void showMechanismInfoList( int index );
    void showSessionInfoList( int index );
    void showObjectsInfoList( int index );

    void showCertificateInfoList( int index, long hObject = -1 );
    void showPublicKeyInfoList( int index, long hObject = -1 );
    void showPrivateKeyInfoList( int index, long hObject = -1 );
    void showSecretKeyInfoList( int index, long hObject = -1 );
    void showDataInfoList( int index, long hObject = -1 );

    void showFindInfoList( long hSession, int nMaxCnt, CK_ATTRIBUTE *pAttrList, int nAttrCnt );

    void showMechaismInfoDetail( QModelIndex index );
    void showObjectsInfoDetail( QModelIndex index );
    void showCertificateInfoDetail( QModelIndex index );
    void showPublicKeyInfoDetail( QModelIndex index );
    void showPrivateKeyInfoDetail( QModelIndex index );
    void showSecretKeyInfoDetail( QModelIndex index );
    void showDataInfoDetail( QModelIndex index );



    void setRightTable( QTableWidget *right_table );
    void removeAllRightTable();
    void addEmptyLine( int row );
    void setRightType( int nType );
    int rightType() { return right_type_; };

    int currentSlotIdx() { return slot_index_; };
    void setCurrentSlotIdx( int index );

    void loadLibray( const QString& filename );

    void viewFileNew( bool bChecked );
    void viewFileOpen( bool bChecked );
    void viewFileUnload( bool bChecked );
    void viewFileShowDock( bool bChecked );

    void viewModuleInit( bool bChecked );
    void viewModuleFinal( bool bChecked );
    void viewModuleOpenSess( bool bChecked );
    void viewModuleCloseSess( bool bChecked );
    void viewModuleCloseAll( bool bChecked );
    void viewModuleLogin( bool bChecked );
    void viewModuleLogout( bool bChecked );

    void viewObjectGenKeyPair( bool bChecked );
    void viewObjectGenKey( bool bChecked );
    void viewObjectCreateData( bool bChecked );
    void viewObjectCreateRSAPubKey( bool bChecked );
    void viewObjectCreateRSAPriKey( bool bChecked );
    void viewObjectCreateECPubKey( bool bChecked );
    void viewObjectCreateECPriKey( bool bChecked );
    void viewObjectCreateEDPubKey( bool bChecked );
    void viewObjectCreateEDPriKey( bool bChecked );
    void viewObjectCreateDSAPubKey( bool bChecked );
    void viewObjectCreateDSAPriKey( bool bChecked );
    void viewObjectCreateKey( bool bChecked );
    void viewObjectDelObject( bool bChecked );
    void viewObjectEditAtt( bool bChecked );
    void viewObjectEditAttList( bool bChecked );
    void viewObjectCopyObject( bool bChecked );
    void viewObjectFindObject( bool bChecked );

    void viewCryptRand( bool bChecked );
    void viewCryptDigest( bool bChecked );
    void viewCryptSign( bool bChecked );
    void viewCryptVerify( bool bChecked );
    void viewCryptEnc( bool bChecked );
    void viewCryptDec( bool bChecked );
    void viewCryptHsmMan( bool bChecked );

    void viewImportCert( bool bChecked );
    void viewImportPFX( bool bChecked );
    void viewImportPriKey( bool bChecked );

    void viewToolInitToken( bool bChecked );
    void viewToolOperState( bool bChecked );
    void viewToolSetPIN( bool bChecked );
    void viewToolInitPIN( bool bChecked );
    void viewToolWrapKey( bool bChecked );
    void viewToolUnwrapKey( bool bChecked );
    void viewToolDeriveKey( bool bChecked );
    void viewToolTypeName( bool bChecked );
    void viewToolMakeCSR( bool bChecked );

    void viewHelpClearLog( bool bChecked );
    void viewHelpHaltLog( bool bChecked );
    void viewHelpSetting( bool bChecked );
    void viewHelpAbout( bool bChecked );

    void viewSetDefault();

private slots:
    void closeEvent(QCloseEvent *event);

public slots:
    void newFile();
    void open();
    void openRecent();
    void quit();
    void unload();
    void P11Initialize();
    void P11Finalize();
    void openSession();
    void closeSession();
    void closeAllSessions();
    void login();
    void logout();
    void generateKeyPair();
    void generateKey();
    void createData();
    void createRSAPublicKey();
    void createRSAPrivateKey();
    void createECPublicKey();
    void createECPrivateKey();
    void createEDPublicKey();
    void createEDPrivateKey();
    void createDSAPublicKey();
    void createDSAPrivateKey();
    void createKey();
    void copyObject();
    void findObject();
    void copyTableObject();
    void deleteObject();
    void editObject();
    void editAttribute();
    void editAttributeList2();
    void editAttributeList();
    void digest();
    void sign();
    void signType();
    void signEach();
    void hsmMan();

    void verify();
    void verifyType();
    void verifyEach();
    void encrypt();
    void encryptType();
    void encryptEach();
    void decrypt();
    void decryptType();
    void decryptEach();
    void importCert();
    void viewCert();
    void viewPriKey();
    void viewPubKkey();
    void importPFX();
    void improtPrivateKey();
    void exportPubKey();
    void exportPriKey();
    void exportCert();
    void makeCSR();
    void makeCSREach();
    void initToken();
    void rand();
    void setPin();
    void initPin();
    void wrapKey();
    void unwrapKey();
    void deriveKey();
    void typeName();
    void licenseInfo();
    void bugIssueReport();
    void qnaDiscussion();
    void about();
    void useLog( bool bEnable = true );
    void settings();
    void operationState();
    void logClear();
    void logToggle();
    void showDock();

    void rightTableClick( QModelIndex index );
    void rightTableDblClick();
    void showRightMenu(QPoint point );

    virtual void dragEnterEvent(QDragEnterEvent *event );
    virtual void dropEvent(QDropEvent *event );

private:
    void baseTableHeader();
    void createViewActions();
    void createActions();
    void createStatusBar();
    void createMemberDlg();

    int openLibrary( const QString libPath );
    void setTitle(const QString strName);

    void adjustForCurrentFile( const QString& filePath );
    void updateRecentActionList();
    void showAttribute( int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj );
    QString stringAttribute( int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj, int *pnLen = NULL );

    void showInfoCommon( CK_OBJECT_HANDLE hObj );
    void showInfoData( CK_OBJECT_HANDLE hObj );
    void showInfoCertCommon( CK_OBJECT_HANDLE hObj );
    void showInfoX509Cert( CK_OBJECT_HANDLE hObj );
    void showInfoKeyCommon( CK_OBJECT_HANDLE hObj );
    void showInfoPublicKey( CK_OBJECT_HANDLE hObj );
    void showInfoPrivateKey( CK_OBJECT_HANDLE hObj );
    void showInfoSecretKey( CK_OBJECT_HANDLE hObj );

    void showInfoRSAValue( CK_OBJECT_HANDLE hObj, bool bPub = false );
    void showInfoDSAValue( CK_OBJECT_HANDLE hObj, bool bPub = false );
    void showInfoECCValue( CK_OBJECT_HANDLE hObj, bool bPub = false );
    void showInfoDHValue( CK_OBJECT_HANDLE hObj, bool bPub = false );
    void showInfoSecretValue( CK_OBJECT_HANDLE hObj);


    void certificateInfoList( long hSession, int nMaxCnt, CK_ATTRIBUTE *pAttrList, int nAttrCnt );
    void publicKeyInfoList( long hSession, int nMaxCnt, CK_ATTRIBUTE *pAttrList, int nAttrCnt );
    void privateKeyInfoList( long hSession, int nMaxCnt, CK_ATTRIBUTE *pAttrList, int nAttrCnt );
    void secretKeyInfoList( long hSession, int nMaxCnt, CK_ATTRIBUTE *pAttrList, int nAttrCnt );
    void dataInfoList( long hSession, int nMaxCnt, CK_ATTRIBUTE *pAttrList, int nAttrCnt );

    bool isView( int nAct );
    void setView( int nAct );
    void unsetView( int nAct );

    QList<QAction *>  recent_file_list_;

    QSplitter       *hsplitter_;
    QDockWidget     *dock_;

    ManTreeView     *left_tree_;
    ManTreeModel    *left_model_;
    QTableWidget    *right_table_;

    QTabWidget      *text_tab_;
    CodeEditor      *info_text_;
    QPlainTextEdit  *log_text_;
    int             right_type_;

    QString         file_path_;

    QList<SlotInfo> slot_infos_;
    int             slot_index_;
    ThreadWork      *th_work_;

    bool            log_halt_;

    HsmManDlg*       hsm_man_dlg_;

    QToolBar* file_tool_;
    QAction* new_act_;
    QAction* open_act_;
    QAction* unload_act_;
    QAction* show_dock_act_;
    QAction* quit_act_;

    QToolBar* module_tool_;
    QAction* init_act_;
    QAction* final_act_;
    QAction* open_sess_act_;
    QAction* close_sess_act_;
    QAction* close_all_act_;
    QAction* login_act_;
    QAction* logout_act_;

    QToolBar* object_tool_;
    QAction* gen_keypair_act_;
    QAction* gen_key_act_;
    QAction* create_data_act_;
    QAction* create_rsa_pub_key_act_;
    QAction* create_rsa_pri_key_act_;
    QAction* create_ec_pub_key_act_;
    QAction* create_ec_pri_key_act_;
    QAction* create_ed_pub_key_act_;
    QAction* create_ed_pri_key_act_;
    QAction* create_dsa_pub_key_act_;
    QAction* create_dsa_pri_key_act_;
    QAction* create_key_act_;
    QAction* del_object_act_;
    QAction* edit_att_act_;
    QAction* edit_att_list_act_;
    QAction* copy_object_act_;
    QAction* find_object_act_;

    QToolBar* crypt_tool_;
    QAction* rand_act_;
    QAction* digest_act_;
    QAction* sign_act_;
    QAction* verify_act_;
    QAction* enc_act_;
    QAction* dec_act_;
    QAction* hsm_man_act_;

    QToolBar* import_tool_;
    QAction* import_cert_act_;
    QAction* import_pfx_act_;
    QAction* import_pri_key_act_;

    QToolBar* tool_tool_;
    QAction* init_token_act_;
    QAction* oper_state_act_;
    QAction* set_pin_act_;
    QAction* init_pin_act_;
    QAction* wrap_key_act_;
    QAction* unwrap_key_act_;
    QAction* derive_key_act_;
    QAction* type_name_act_;
    QAction* make_csr_act_;

    QToolBar* help_tool_;
    QAction* clear_log_act_;
    QAction* halt_log_act_;
    QAction* setting_act_;
    QAction* lcn_info_act_;
    QAction* bug_issue_act_;
    QAction* qna_act_;
    QAction* about_act_;
};

#endif // MAINWINDOW_H
