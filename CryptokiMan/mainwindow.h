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

class ManTreeView;
class ManTreeModel;
class ManTreeItem;
class ThreadWork;

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

    QList<SlotInfo>& getSlotInfos() { return slot_infos_; };
    ManTreeItem* currentTreeItem();
    ManTreeItem* getRootItem();

    void info( QString strInfo, QColor cr = QColor(0x00, 0x00, 0x00) );
    void info_w( QString strInfo );

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
    void createDSAPublicKey();
    void createDSAPrivateKey();
    void createKey();
    void copyObject();
    void copyTableObject();
    void deleteObject();
    void editObject();
    void editAttribute();
    void digest();
    void sign();
    void signType();
    void signEach();

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
    void importPFX();
    void improtPrivateKey();
    void initToken();
    void rand();
    void setPin();
    void initPin();
    void wrapKey();
    void unwrapKey();
    void deriveKey();
    void licenseInfo();
    void bugIssueReport();
    void qnaDiscussion();
    void about();
    void logView( bool bShow = true );
    void settings();
    void operationState();
    void logClear();
    void logToggle();
    void showDock();

    void rightTableClick( QModelIndex index );
    void showRightMenu(QPoint point );

    virtual void dragEnterEvent(QDragEnterEvent *event );
    virtual void dropEvent(QDropEvent *event );

private:
    void baseTableHeader();
    void createActions();
    void createStatusBar();
    int openLibrary( const QString libPath );
    void setTitle(const QString strName);

    void adjustForCurrentFile( const QString& filePath );
    void updateRecentActionList();
    void showAttribute( int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj );
    QString stringAttribute( int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj );

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

    QList<QAction *>  recent_file_list_;

    QSplitter       *hsplitter_;
    QDockWidget     *dock_;

    ManTreeView     *left_tree_;
    ManTreeModel    *left_model_;
    QTableWidget    *right_table_;

    QTabWidget      *text_tab_;
    QTextEdit       *info_text_;
    QTextEdit       *log_text_;
    int             right_type_;

    QString         file_path_;

    QList<SlotInfo> slot_infos_;
    int             slot_index_;
    ThreadWork      *th_work_;

    bool            log_halt_;
};

#endif // MAINWINDOW_H
