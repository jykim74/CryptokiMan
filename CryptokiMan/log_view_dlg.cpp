#include <QDateTime>
#include "log_view_dlg.h"

const QStringList kLogLevelList = { "None", "Error", "Info", "Warning", "Debug" };

LogViewDlg::LogViewDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(logClear()));
    connect( mSaveBtn, SIGNAL(clicked()), this, SLOT(logSave()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(logClose()));

    mLogLevelCombo->addItems( kLogLevelList );
    mLogLevelCombo->setCurrentIndex(2);
}

LogViewDlg::~LogViewDlg()
{

}

void LogViewDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void LogViewDlg::closeEvent(QCloseEvent *)
{

}

void LogViewDlg::initialize()
{

}

void LogViewDlg::logClear()
{
    mLogText->clear();
}

void LogViewDlg::logSave()
{

}

void LogViewDlg::logClose()
{
    this->hide();
}

void LogViewDlg::log( QString strLog )
{
    int nLevel = mLogLevelCombo->currentIndex();
    if( nLevel < 2 ) return;

    QDateTime date;
    date.setTime_t( time(NULL));
    QString strMsg;

    strMsg = QString("[I][%1] %2\n" ).arg( date.toString( "yyyy-MM-dd HH:mm:ss") ).arg( strLog );

    QTextCursor cursor = mLogText->textCursor();

    QTextCharFormat format;
    format.setForeground(QColor(0x00,0x00,0x00));
    cursor.mergeCharFormat(format);

    cursor.insertText( strMsg );
    cursor.movePosition(QTextCursor::End);
    mLogText->setTextCursor( cursor );
    mLogText->repaint();
}

void LogViewDlg::ilog( const QString strLog )
{
    log( strLog );
}

void LogViewDlg::elog( const QString strLog )
{
    int nLevel = mLogLevelCombo->currentIndex();
    if( nLevel < 1 ) return;

    QDateTime date;
    date.setTime_t( time(NULL));
    QString strMsg;

    strMsg = QString("[E][%1] %2\n" ).arg( date.toString( "yyyy-MM-dd HH:mm:ss") ).arg( strLog );

    QTextCursor cursor = mLogText->textCursor();
    QTextCharFormat format;
    format.setForeground(QColor(0xFF,0x00,0x00));
    cursor.mergeCharFormat(format);

    cursor.insertText( strMsg );
    cursor.movePosition(QTextCursor::End);
    mLogText->setTextCursor( cursor );
    mLogText->repaint();
}

void LogViewDlg::wlog( const QString strLog )
{
    int nLevel = mLogLevelCombo->currentIndex();
    if( nLevel < 3 ) return;

    QDateTime date;
    date.setTime_t( time(NULL));
    QString strMsg;

    strMsg = QString("[W][%1] %2\n" ).arg( date.toString( "yyyy-MM-dd HH:mm:ss") ).arg( strLog );

    QTextCursor cursor = mLogText->textCursor();

    QTextCharFormat format;
    format.setForeground(QColor(0x66, 0x33, 0x00));
    cursor.mergeCharFormat(format);

    cursor.insertText( strMsg );
    cursor.movePosition(QTextCursor::End);
    mLogText->setTextCursor( cursor );
    mLogText->repaint();
}

void LogViewDlg::dlog( const QString strLog )
{
    int nLevel = mLogLevelCombo->currentIndex();
    if( nLevel < 4 ) return;

    QDateTime date;
    date.setTime_t( time(NULL));
    QString strMsg;

    strMsg = QString("[D][%1] %2\n" ).arg( date.toString( "yyyy-MM-dd HH:mm:ss") ).arg( strLog );

    QTextCursor cursor = mLogText->textCursor();

    QTextCharFormat format;
    format.setForeground(QColor(0x00,0x00,0xFF));
    cursor.mergeCharFormat(format);

    cursor.insertText( strMsg );
    cursor.movePosition(QTextCursor::End);
    mLogText->setTextCursor( cursor );
    mLogText->repaint();
}

void LogViewDlg::write( const QString strLog )
{
    QTextCursor cursor = mLogText->textCursor();

    QTextCharFormat format;
    format.setForeground(QColor(0x00,0x00,0x00));
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );
    cursor.movePosition( QTextCursor::End );
    mLogText->setTextCursor( cursor );
    mLogText->repaint();
}
