#ifndef DECRYPTTHREAD_H
#define DECRYPTTHREAD_H

#include <QThread>

class DecryptThread : public QThread
{
    Q_OBJECT

public:
    DecryptThread();
    ~DecryptThread();

    void setSession( long uSession );
    void setSrcFile( const QString strSrcFile );
    void setDstFile( const QString strDstFile );

signals:
    void taskFinished();
    void taskUpdate( int nUpdate );

protected:
    void run() override;
    long session_;
    QString src_file_;
    QString dst_file_;
};

#endif // DECRYPTTHREAD_H
