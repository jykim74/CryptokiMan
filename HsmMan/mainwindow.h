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

private:
    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;

    ManTreeView     *left_tree_;
    ManTreeModel    *left_model_;
    QTableWidget    *right_table_;
    QTextEdit       *right_text_;

};

#endif // MAINWINDOW_H
