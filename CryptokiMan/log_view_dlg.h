#ifndef LOG_VIEW_DLG_H
#define LOG_VIEW_DLG_H

#include <QDialog>
#include "ui_log_view_dlg.h"

namespace Ui {
class LogViewDlg;
}

class LogViewDlg : public QDialog, public Ui::LogViewDlg
{
    Q_OBJECT

public:
    explicit LogViewDlg(QWidget *parent = nullptr);
    ~LogViewDlg();

    void log( const QString strLog );
    void ilog( const QString strLog );
    void elog( const QString strLog );
    void wlog( const QString strLog );
    void dlog( const QString strLog );
    void write( const QString strLog );

private slots:
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *);
    void logClear();
    void logSave();
    void logClose();

private:
    void initialize();

    Q_DISABLE_COPY(LogViewDlg);
};

#endif // LOG_VIEW_DLG_H
