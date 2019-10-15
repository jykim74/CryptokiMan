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
    JSP11_CTX* getP11CTX() { return p11_ctx_; };
    QList<SlotInfo>& getSlotInfos() { return slot_infos_; };


private slots:
    void newFile();
    void open();
    void quit();
    void unload();
    void openSession();
    void closeSession();
    void closeAllSessions();
    void login();
    void logout();
    void generateKeyPair();
    void generateKey();
    void generateData();
    void generateRSAPublicKey();
    void generateRSAPrivateKey();
    void generateECPublicKey();
    void generateECPrivateKey();
    void createKey();
    void deleteObject();
    void editAttribute();
    void digest();
    void sign();
    void verify();
    void encrypt();
    void decrypt();
    void importCert();
    void importPFX();
    void improtPrivateKey();
    void initToken();
    void rand();
    void setPin();
    void initPin();
    void wrapKey();
    void unwrapKey();
    void deriveKey();
    void about();
    void logView();

    void rightTableClick( QModelIndex index );



private:
    void createTableMenu();
    void createActions();
    void createStatusBar();

    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;

    ManTreeView     *left_tree_;
    ManTreeModel    *left_model_;
    QTableWidget    *right_table_;
    QTextEdit       *right_text_;

    JSP11_CTX       *p11_ctx_;
    QString         file_path_;

    QList<SlotInfo> slot_infos_;
};

#endif // MAINWINDOW_H
