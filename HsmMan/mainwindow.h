#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSplitter>
#include <QTreeView>
#include <QTableWidget>
#include <QTextEdit>

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

private slots:
    void newFile();
    void open();
    void quit();
    void unload();
    void openSession();
    void closeSession();

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

    void            *p11_ctx_;
    QString         file_path_;

};

#endif // MAINWINDOW_H
